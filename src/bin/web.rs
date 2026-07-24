//! Local web front end.
//!
//! A browser can neither reach the USB reader nor relay the mutual
//! authentication, so this binary keeps the reader in a background thread and
//! streams what it finds to the page over Server-Sent Events.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::get;
use chrono::Local;
use clap::Parser;
use futures_util::{Stream, StreamExt};
use serde::Serialize;
use serde_json::json;
use suica_viewer::card::SharedDriver;
use suica_viewer::card_data::CardData;
use suica_viewer::{
    AuthClient, CardDataService, CardSession, SYSTEM_CODE, StationCodeLookup, reader,
    resolve_server_url,
};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

const INDEX_HTML: &str = include_str!("../../assets/web/index.html");
const DEMO_CARD_JSON: &str = include_str!("../../assets/web/demo_card.json");

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8765;

/// Buffered events per subscriber. Generous enough that a page which stalls
/// briefly still catches up rather than being dropped.
const EVENT_BUFFER: usize = 256;

/// Consecutive unanswered presence checks before the card counts as gone.
///
/// One missed check is ordinary RF noise; a run of them means the card left the
/// field. Request Response is answered in every card mode, so a small run is
/// already conclusive.
const ABSENT_CHECKS_BEFORE_REMOVAL: u32 = 3;

#[derive(Parser, Debug)]
#[command(
    name = "suica-viewer-web",
    about = "Suica Viewer のローカル Web GUI を起動します。",
    version
)]
struct Args {
    /// バインドするホスト（既定: 127.0.0.1）。LAN 公開時はカード情報がネットワークに流れる点に注意してください。
    #[arg(long, default_value = DEFAULT_HOST)]
    host: IpAddr,

    /// ポート（既定: 8765）。
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// 認証サーバの URL（未指定なら AUTH_SERVER_URL 環境変数か既定値）。
    #[arg(long, value_name = "URL")]
    server: Option<String>,

    /// 起動時にブラウザを自動で開かない。
    #[arg(long)]
    no_browser: bool,

    /// リーダーを使わず、疑似カードで UI をプレビューする。
    #[arg(long)]
    demo: bool,
}

// --------------------------------------------------------------------------- //
// Events                                                                      //
// --------------------------------------------------------------------------- //

/// One message pushed to the page. The tag and field names are the SSE contract
/// the bundled page parses.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Event {
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

impl Event {
    fn status(state: &'static str, message: impl Into<String>) -> Self {
        Self::Status {
            state,
            message: message.into(),
        }
    }

    fn progress(value: f32) -> Self {
        Self::Progress {
            // The page shows one decimal. Rounding in f64 keeps the JSON exact:
            // an f32 widened after rounding serializes as 45.099998474121094.
            value: (f64::from(value) * 10.0).round() / 10.0,
        }
    }

    fn card(data: Arc<CardData>) -> Self {
        Self::Card {
            // The offset is spelled out rather than abbreviated: a local time
            // carries no zone name, so `%Z` would render the offset anyway.
            read_at: Local::now().format("%Y-%m-%d %H:%M:%S %:z").to_string(),
            data,
        }
    }
}

// --------------------------------------------------------------------------- //
// Hub                                                                         //
// --------------------------------------------------------------------------- //

/// Fans reader events out to connected browsers.
///
/// The reader runs on a plain thread while subscribers live on the async
/// runtime, so the two meet at a broadcast channel. The latest status and card
/// are retained to seed a page that connects after the fact.
struct ReaderHub {
    sender: broadcast::Sender<Event>,
    latest: Mutex<Latest>,
    stopped: AtomicBool,
}

struct Latest {
    status: Event,
    card: Option<Event>,
}

impl ReaderHub {
    fn new() -> Self {
        Self {
            sender: broadcast::channel(EVENT_BUFFER).0,
            latest: Mutex::new(Latest {
                status: Event::status("initializing", "NFC リーダーを初期化しています…"),
                card: None,
            }),
            stopped: AtomicBool::new(false),
        }
    }

    fn publish(&self, event: Event) {
        {
            let mut latest = self.latest.lock().expect("hub state poisoned");
            match &event {
                Event::Status { .. } => latest.status = event.clone(),
                Event::Card { .. } => latest.card = Some(event.clone()),
                Event::Removed => latest.card = None,
                _ => {}
            }
        }
        // No subscribers is the normal state before a page connects.
        let _ = self.sender.send(event);
    }

    /// Returns the events a newly connected page needs, plus the live feed.
    ///
    /// The subscription is taken while the snapshot is held so an event
    /// published in between is neither missed nor delivered twice.
    fn subscribe(&self) -> (Vec<Event>, broadcast::Receiver<Event>) {
        let latest = self.latest.lock().expect("hub state poisoned");
        let receiver = self.sender.subscribe();
        let mut seed = vec![latest.status.clone()];
        if let Some(card) = &latest.card {
            seed.push(card.clone());
        }
        (seed, receiver)
    }

    fn latest_card(&self) -> Option<Event> {
        self.latest.lock().expect("hub state poisoned").card.clone()
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }
}

// --------------------------------------------------------------------------- //
// Reader worker                                                               //
// --------------------------------------------------------------------------- //

/// Owns the reader for the life of the process and publishes what it reads.
fn run_reader(hub: Arc<ReaderHub>, service: CardDataService, server_url: String) {
    hub.publish(Event::status(
        "initializing",
        "NFC リーダーを初期化しています…",
    ));

    let mut card_reader = match reader::open() {
        Ok(reader) => reader,
        Err(message) => {
            hub.publish(Event::Error {
                message: format!("NFC リーダーを初期化できません: {message}"),
            });
            return;
        }
    };

    let mut client = match AuthClient::new(&server_url) {
        Ok(client) => client,
        Err(error) => {
            hub.publish(Event::Error {
                message: format!("認証サーバの設定が不正です: {error}"),
            });
            return;
        }
    };

    let mut driver = SharedDriver::new(card_reader.driver_mut());
    hub.publish(Event::status("waiting", "カードをかざしてください。"));

    while !hub.is_stopped() {
        let mut card = match CardSession::poll(&mut driver, SYSTEM_CODE) {
            Ok(Some(card)) => card,
            Ok(None) => {
                std::thread::sleep(reader::POLL_INTERVAL);
                continue;
            }
            Err(error) => {
                hub.publish(Event::status("waiting", format!("読み取りエラー: {error}")));
                std::thread::sleep(reader::POLL_INTERVAL);
                continue;
            }
        };

        hub.publish(Event::status("reading", "カード情報を取得しています…"));
        hub.publish(Event::progress(5.0));

        client.reset();
        let progress_hub = Arc::clone(&hub);
        let mut progress = move |value: f32| progress_hub.publish(Event::progress(value));

        match service.collect(&mut client, &mut card, Some(&mut progress)) {
            Ok(data) => {
                hub.publish(Event::card(Arc::new(data)));
                hub.publish(Event::status("done", "カード情報を読み取りました。"));
            }
            Err(error) => {
                hub.publish(Event::status(
                    "waiting",
                    format!("カード情報の取得に失敗しました: {error}"),
                ));
            }
        }

        wait_for_removal(&hub, &mut card);
    }
}

/// Blocks until the card leaves the field, then announces it.
///
/// Without this the loop would immediately re-read the card still sitting on
/// the reader, so a single tap would replay forever.
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

    hub.publish(Event::Removed);
    hub.publish(Event::status("waiting", "カードをかざしてください。"));
}

/// Feeds the built-in sample card so the UI can be previewed without a reader.
fn run_demo(hub: Arc<ReaderHub>) {
    let card: CardData = match serde_json::from_str(DEMO_CARD_JSON) {
        Ok(card) => card,
        Err(error) => {
            hub.publish(Event::Error {
                message: format!("デモカードの読み込みに失敗しました: {error}"),
            });
            return;
        }
    };

    hub.publish(Event::status(
        "waiting",
        "デモモード: 疑似カードを読み取ります…",
    ));
    std::thread::sleep(Duration::from_millis(800));
    hub.publish(Event::status("reading", "カード情報を取得しています…"));
    for value in [20.0, 45.0, 70.0, 90.0, 100.0] {
        std::thread::sleep(Duration::from_millis(120));
        hub.publish(Event::progress(value));
    }
    hub.publish(Event::card(Arc::new(card)));
    hub.publish(Event::status("done", "デモカードを読み取りました。"));
}

// --------------------------------------------------------------------------- //
// HTTP                                                                        //
// --------------------------------------------------------------------------- //

fn app(hub: Arc<ReaderHub>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/card", get(latest_card))
        .route("/api/stream", get(stream))
        .with_state(hub)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn latest_card(State(hub): State<Arc<ReaderHub>>) -> impl IntoResponse {
    match hub.latest_card() {
        Some(Event::Card { read_at, data }) => Json(json!({"card": data, "read_at": read_at})),
        _ => Json(json!({ "card": null })),
    }
}

async fn stream(
    State(hub): State<Arc<ReaderHub>>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let (seed, receiver) = hub.subscribe();

    let seed = futures_util::stream::iter(seed);
    // A lagging subscriber only loses intermediate progress ticks; the next
    // status or card event brings the page back in sync.
    let live = BroadcastStream::new(receiver).filter_map(|event| async move { event.ok() });

    Sse::new(seed.chain(live).map(|event| {
        Ok(SseEvent::default()
            .json_data(&event)
            .unwrap_or_else(|error| {
                SseEvent::default().data(
                    json!({
                        "type": "error",
                        "message": format!("イベントの生成に失敗しました: {error}"),
                    })
                    .to_string(),
                )
            }))
    }))
    .keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

// --------------------------------------------------------------------------- //
// Entry point                                                                 //
// --------------------------------------------------------------------------- //

#[tokio::main]
async fn main() -> std::process::ExitCode {
    env_logger::init();
    let args = Args::parse();

    match run(args).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
    let hub = Arc::new(ReaderHub::new());
    let server_url = resolve_server_url(args.server.as_deref());

    let worker_hub = Arc::clone(&hub);
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
    .map_err(|error| format!("リーダースレッドを起動できません: {error}"))?;

    let address = SocketAddr::new(args.host, args.port);
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| format!("{address} をバインドできません: {error}"))?;

    let url = format!("http://{address}/");
    println!("Suica Viewer Web GUI: {url}");
    if args.demo {
        println!("（デモモード: 実際のリーダーは使用しません）");
    }
    if !args.no_browser && webbrowser::open(&url).is_err() {
        eprintln!("ブラウザを開けませんでした。{url} を手動で開いてください。");
    }

    let shutdown_hub = Arc::clone(&hub);
    axum::serve(listener, app(Arc::clone(&hub)))
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown_hub.stop();
        })
        .await
        .map_err(|error| format!("サーバの実行に失敗しました: {error}"))?;

    hub.stop();
    // The reader thread checks the stop flag between polls, so this returns
    // within one poll interval rather than hanging on shutdown.
    let _ = worker.join();
    Ok(())
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
    fn the_bundled_page_is_self_contained() {
        assert!(INDEX_HTML.contains("/api/stream"));
        assert!(INDEX_HTML.contains("<script>"));
    }

    #[test]
    fn events_serialize_to_the_shape_the_page_parses() {
        let status = serde_json::to_value(Event::status("waiting", "x")).unwrap();
        assert_eq!(status["type"], "status");
        assert_eq!(status["state"], "waiting");
        assert_eq!(status["message"], "x");

        let progress = serde_json::to_value(Event::progress(45.06)).unwrap();
        assert_eq!(progress["type"], "progress");
        assert_eq!(progress["value"], 45.1);

        let removed = serde_json::to_value(Event::Removed).unwrap();
        assert_eq!(removed["type"], "removed");
        assert_eq!(removed.as_object().unwrap().len(), 1);
    }

    #[test]
    fn a_card_event_nests_the_data_under_the_expected_keys() {
        let card: CardData = serde_json::from_str(DEMO_CARD_JSON).unwrap();
        let event = serde_json::to_value(Event::card(Arc::new(card))).unwrap();
        assert_eq!(event["type"], "card");
        assert!(event["read_at"].is_string());
        assert_eq!(event["data"]["attribute"]["balance"], 3820);
    }

    #[test]
    fn a_late_subscriber_is_seeded_with_the_current_status_and_card() {
        let hub = ReaderHub::new();
        let (seed, _receiver) = hub.subscribe();
        assert_eq!(seed.len(), 1, "a fresh hub seeds only its status");

        let card: CardData = serde_json::from_str(DEMO_CARD_JSON).unwrap();
        hub.publish(Event::status("done", "read"));
        hub.publish(Event::card(Arc::new(card)));

        let (seed, _receiver) = hub.subscribe();
        assert_eq!(seed.len(), 2);
        assert!(matches!(seed[0], Event::Status { state: "done", .. }));
        assert!(matches!(seed[1], Event::Card { .. }));

        // A removal clears the retained card so a reconnecting page does not
        // resurrect a card that is no longer on the reader.
        hub.publish(Event::Removed);
        let (seed, _receiver) = hub.subscribe();
        assert_eq!(seed.len(), 1);
    }

    #[test]
    fn publishing_without_subscribers_is_not_an_error() {
        let hub = ReaderHub::new();
        hub.publish(Event::progress(10.0));
        assert!(hub.latest_card().is_none());
    }
}
