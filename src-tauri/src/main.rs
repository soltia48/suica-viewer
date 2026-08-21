//! Tauri desktop front end.
//!
//! The WebView cannot access the USB reader directly, so the reader remains on
//! a Rust worker thread. Its state is streamed to the Preact UI over a Tauri
//! IPC channel; no local HTTP server or open browser is involved.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use chrono::Local;
use clap::Parser;
use serde::Serialize;
use suica_viewer::card::SharedDriver;
use suica_viewer::card_data::CardData;
use suica_viewer::{
    AuthClient, CardDataService, CardSession, SYSTEM_CODE, StationCodeLookup, reader,
    resolve_server_url,
};
use tauri::ipc::Channel;

const DEMO_CARD_JSON: &str = include_str!("../assets/demo_card.json");
const ABSENT_CHECKS_BEFORE_REMOVAL: u32 = 3;

#[derive(Parser, Debug)]
#[command(
    name = "suica-viewer",
    about = "Suica Viewer のデスクトップ GUI を起動します。",
    version
)]
struct Args {
    /// 認証サーバの URL（未指定なら AUTH_SERVER_URL 環境変数か既定値）。
    #[arg(long, value_name = "URL")]
    server: Option<String>,

    /// リーダーを使わず、疑似カードで UI をプレビューする。
    #[arg(long)]
    demo: bool,
}

/// A single message delivered to the Preact application.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ReaderEvent {
    Status {
        state: &'static str,
        message: String,
    },
    Progress {
        value: f64,
    },
    Card {
        read_at: String,
        data: Arc<CardData>,
    },
    Error {
        message: String,
    },
    Removed,
}

impl ReaderEvent {
    fn status(state: &'static str, message: impl Into<String>) -> Self {
        Self::Status {
            state,
            message: message.into(),
        }
    }

    fn progress(value: f32) -> Self {
        Self::Progress {
            // Keep the JSON value stable when widening f32 to f64.
            value: (f64::from(value) * 10.0).round() / 10.0,
        }
    }

    fn card(data: Arc<CardData>) -> Self {
        Self::Card {
            read_at: Local::now().format("%Y-%m-%d %H:%M:%S %:z").to_string(),
            data,
        }
    }
}

struct Latest {
    status: ReaderEvent,
    card: Option<ReaderEvent>,
}

/// Shared state between the blocking reader worker and the Tauri commands.
struct ReaderHub {
    latest: Mutex<Latest>,
    subscribers: Mutex<Vec<Channel<ReaderEvent>>>,
    stopped: AtomicBool,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl ReaderHub {
    fn new() -> Self {
        Self {
            latest: Mutex::new(Latest {
                status: ReaderEvent::status("initializing", "NFC リーダーを初期化しています…"),
                card: None,
            }),
            subscribers: Mutex::new(Vec::new()),
            stopped: AtomicBool::new(false),
            worker: Mutex::new(None),
        }
    }

    fn publish(&self, event: ReaderEvent) {
        {
            let mut latest = self.latest.lock().expect("hub state poisoned");
            match &event {
                ReaderEvent::Status { .. } | ReaderEvent::Error { .. } => {
                    latest.status = event.clone();
                }
                ReaderEvent::Card { .. } => latest.card = Some(event.clone()),
                ReaderEvent::Removed => latest.card = None,
                ReaderEvent::Progress { .. } => {}
            }
        }

        // A closed/reloaded WebView makes send fail. Removing it here avoids
        // retaining stale JavaScript callbacks for the lifetime of the app.
        self.subscribers
            .lock()
            .expect("subscriber list poisoned")
            .retain(|subscriber| subscriber.send(event.clone()).is_ok());
    }

    /// Atomically seed a new subscriber and attach it to the live feed.
    ///
    /// Holding `latest` until the channel has been registered means a publish
    /// can neither slip between the snapshot and the subscription nor appear
    /// twice.
    fn subscribe(&self, subscriber: Channel<ReaderEvent>) {
        let latest = self.latest.lock().expect("hub state poisoned");
        if subscriber.send(latest.status.clone()).is_err() {
            return;
        }
        if let Some(card) = &latest.card
            && subscriber.send(card.clone()).is_err()
        {
            return;
        }
        self.subscribers
            .lock()
            .expect("subscriber list poisoned")
            .push(subscriber);
    }

    fn set_worker(&self, worker: JoinHandle<()>) {
        *self.worker.lock().expect("worker handle poisoned") = Some(worker);
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    fn join_worker(&self) {
        if let Some(worker) = self.worker.lock().expect("worker handle poisoned").take() {
            let _ = worker.join();
        }
    }
}

struct AppState {
    hub: Arc<ReaderHub>,
}

#[tauri::command]
fn reader_events(on_event: Channel<ReaderEvent>, state: tauri::State<'_, AppState>) {
    state.hub.subscribe(on_event);
}

fn run_reader(hub: Arc<ReaderHub>, service: CardDataService, server_url: String) {
    hub.publish(ReaderEvent::status(
        "initializing",
        "NFC リーダーを初期化しています…",
    ));

    let mut card_reader = match reader::open() {
        Ok(reader) => reader,
        Err(message) => {
            hub.publish(ReaderEvent::Error {
                message: format!("NFC リーダーを初期化できません: {message}"),
            });
            return;
        }
    };

    let mut client = match AuthClient::new(&server_url) {
        Ok(client) => client,
        Err(error) => {
            hub.publish(ReaderEvent::Error {
                message: format!("認証サーバの設定が不正です: {error}"),
            });
            return;
        }
    };

    let mut driver = SharedDriver::new(card_reader.driver_mut());
    hub.publish(ReaderEvent::status("waiting", "カードをかざしてください。"));

    while !hub.is_stopped() {
        let mut card = match CardSession::poll(&mut driver, SYSTEM_CODE) {
            Ok(Some(card)) => card,
            Ok(None) => {
                std::thread::sleep(reader::POLL_INTERVAL);
                continue;
            }
            Err(error) => {
                hub.publish(ReaderEvent::status(
                    "waiting",
                    format!("読み取りエラー: {error}"),
                ));
                std::thread::sleep(reader::POLL_INTERVAL);
                continue;
            }
        };

        hub.publish(ReaderEvent::status(
            "reading",
            "カード情報を取得しています…",
        ));
        hub.publish(ReaderEvent::progress(5.0));

        client.reset();
        let progress_hub = Arc::clone(&hub);
        let mut progress = move |value: f32| {
            progress_hub.publish(ReaderEvent::progress(value));
        };

        match service.collect(&mut client, &mut card, Some(&mut progress)) {
            Ok(data) => {
                hub.publish(ReaderEvent::card(Arc::new(data)));
                hub.publish(ReaderEvent::status("done", "カード情報を読み取りました。"));
            }
            Err(error) => {
                hub.publish(ReaderEvent::status(
                    "waiting",
                    format!("カード情報の取得に失敗しました: {error}"),
                ));
            }
        }

        wait_for_removal(&hub, &mut card);
    }
}

fn wait_for_removal(hub: &ReaderHub, card: &mut CardSession<'_, '_>) {
    let mut misses = 0;
    while !hub.is_stopped() {
        if card.is_present() {
            misses = 0;
        } else {
            misses += 1;
            if misses >= ABSENT_CHECKS_BEFORE_REMOVAL {
                break;
            }
        }
        std::thread::sleep(reader::POLL_INTERVAL);
    }

    hub.publish(ReaderEvent::Removed);
    hub.publish(ReaderEvent::status("waiting", "カードをかざしてください。"));
}

fn run_demo(hub: Arc<ReaderHub>) {
    let card: CardData = match serde_json::from_str(DEMO_CARD_JSON) {
        Ok(card) => card,
        Err(error) => {
            hub.publish(ReaderEvent::Error {
                message: format!("デモカードの読み込みに失敗しました: {error}"),
            });
            return;
        }
    };

    hub.publish(ReaderEvent::status(
        "waiting",
        "デモモード: 疑似カードを読み取ります…",
    ));
    std::thread::sleep(Duration::from_millis(800));
    hub.publish(ReaderEvent::status(
        "reading",
        "カード情報を取得しています…",
    ));
    for value in [20.0, 45.0, 70.0, 90.0, 100.0] {
        std::thread::sleep(Duration::from_millis(120));
        hub.publish(ReaderEvent::progress(value));
    }
    hub.publish(ReaderEvent::card(Arc::new(card)));
    hub.publish(ReaderEvent::status("done", "デモカードを読み取りました。"));
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    let server_url = resolve_server_url(args.server.as_deref());
    let hub = Arc::new(ReaderHub::new());
    let setup_hub = Arc::clone(&hub);
    let shutdown_hub = Arc::clone(&hub);

    tauri::Builder::default()
        .manage(AppState {
            hub: Arc::clone(&hub),
        })
        .invoke_handler(tauri::generate_handler![reader_events])
        .setup(move |_| {
            let worker_hub = Arc::clone(&setup_hub);
            let worker = if args.demo {
                std::thread::Builder::new()
                    .name("nfc-demo".into())
                    .spawn(move || run_demo(worker_hub))
            } else {
                let service = CardDataService::new(StationCodeLookup::new());
                std::thread::Builder::new()
                    .name("nfc-reader".into())
                    .spawn(move || run_reader(worker_hub, service, server_url))
            }
            .map_err(std::io::Error::other)?;
            setup_hub.set_worker(worker);
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("Tauri アプリを起動できませんでした")
        .run(move |_, event| {
            if let tauri::RunEvent::Exit = event {
                shutdown_hub.stop();
                shutdown_hub.join_worker();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_demo_card_parses_into_the_shared_shape() {
        let card: CardData = serde_json::from_str(DEMO_CARD_JSON).expect("demo card should parse");
        assert!(card.has_commuter_pass());
        assert_eq!(card.attribute.balance, 3820);
        assert!(!card.transaction_history.is_empty());
    }

    #[test]
    fn events_serialize_to_the_shape_the_preact_app_parses() {
        let status = serde_json::to_value(ReaderEvent::status("waiting", "x")).unwrap();
        assert_eq!(status["type"], "status");
        assert_eq!(status["state"], "waiting");
        assert_eq!(status["message"], "x");

        let progress = serde_json::to_value(ReaderEvent::progress(45.06)).unwrap();
        assert_eq!(progress["type"], "progress");
        assert_eq!(progress["value"], 45.1);

        let removed = serde_json::to_value(ReaderEvent::Removed).unwrap();
        assert_eq!(removed["type"], "removed");
        assert_eq!(removed.as_object().unwrap().len(), 1);
    }

    #[test]
    fn a_card_event_nests_the_data_under_the_expected_keys() {
        let card: CardData = serde_json::from_str(DEMO_CARD_JSON).unwrap();
        let event = serde_json::to_value(ReaderEvent::card(Arc::new(card))).unwrap();
        assert_eq!(event["type"], "card");
        assert!(event["read_at"].is_string());
        assert_eq!(event["data"]["attribute"]["balance"], 3820);
    }

    #[test]
    fn publishing_without_subscribers_retains_the_latest_card() {
        let hub = ReaderHub::new();
        let card: CardData = serde_json::from_str(DEMO_CARD_JSON).unwrap();
        hub.publish(ReaderEvent::card(Arc::new(card)));
        assert!(hub.latest.lock().unwrap().card.is_some());

        hub.publish(ReaderEvent::Removed);
        assert!(hub.latest.lock().unwrap().card.is_none());
    }
}
