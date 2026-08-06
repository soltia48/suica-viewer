//! Console front end: taps one card and prints what is on it.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use clap::Parser;
use suica_viewer::card::SharedDriver;
use suica_viewer::card_data::{CardData, GateEntry, PaidTicketEntry, TransactionEntry};
use suica_viewer::utils::{format_region, format_yen, thousands};
use suica_viewer::{
    AuthClient, CardDataService, CardSession, SYSTEM_CODE, StationCodeLookup, reader,
    resolve_server_url,
};
use unicode_width::UnicodeWidthChar;

#[derive(Parser, Debug)]
#[command(
    name = "suica-viewer",
    about = "FeliCa 交通系ICカードの詳細情報を読み取って表示します。",
    version
)]
struct Args {
    /// 人間向けの表ではなく JSON を出力する。
    #[arg(long)]
    json: bool,

    /// 装置番号・生コードなどの詳細フィールドも表示する。
    #[arg(short, long)]
    verbose: bool,

    /// ANSI カラー出力を無効化する（NO_COLOR / 非TTY でも自動的に無効）。
    #[arg(long)]
    no_color: bool,

    /// 認証サーバの URL（未指定なら AUTH_SERVER_URL 環境変数か既定値）。
    #[arg(long, value_name = "URL")]
    server: Option<String>,
}

// --------------------------------------------------------------------------- //
// Terminal helpers                                                            //
// --------------------------------------------------------------------------- //

fn char_width(ch: char) -> usize {
    // Full-width glyphs occupy two terminal columns; anything the width table
    // reports as zero-width still needs one column reserved so the alignment
    // does not collapse.
    UnicodeWidthChar::width(ch).unwrap_or(1).max(1)
}

/// Terminal column width of `text`, counting full-width glyphs as 2.
fn display_width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

fn truncate(text: &str, width: usize) -> String {
    if display_width(text) <= width {
        return text.to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let next = char_width(ch);
        if used + next > width.saturating_sub(1) {
            break;
        }
        out.push(ch);
        used += next;
    }
    out.push('…');
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Align {
    Left,
    Right,
}

/// Pads or truncates `text` to exactly `width` terminal columns.
fn fit(text: &str, width: usize, align: Align) -> String {
    let text = truncate(text, width);
    let padding = " ".repeat(width.saturating_sub(display_width(&text)));
    match align {
        Align::Left => format!("{text}{padding}"),
        Align::Right => format!("{padding}{text}"),
    }
}

/// ANSI styling that collapses to a no-op when color is disabled.
#[derive(Clone, Copy)]
struct Palette {
    enabled: bool,
}

impl Palette {
    fn wrap(self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\u{1b}[{code}m{text}\u{1b}[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(self, text: &str) -> String {
        self.wrap("1", text)
    }

    fn dim(self, text: &str) -> String {
        self.wrap("2", text)
    }

    fn cyan(self, text: &str) -> String {
        self.wrap("36", text)
    }

    fn green(self, text: &str) -> String {
        self.wrap("32", text)
    }

    fn red(self, text: &str) -> String {
        self.wrap("31", text)
    }
}

// --------------------------------------------------------------------------- //
// Value formatting                                                            //
// --------------------------------------------------------------------------- //

fn yen_compact(value: u16) -> String {
    format!("¥{}", thousands(i64::from(value)))
}

fn format_delta(value: Option<i64>) -> String {
    match value {
        Some(value) if value > 0 => format!("+{}", thousands(value)),
        Some(value) => thousands(value),
        None => "—".to_string(),
    }
}

/// Blanks out a station name the dataset could not resolve.
fn clean_station(name: Option<&String>) -> &str {
    match name {
        Some(name) if !name.is_empty() && !name.starts_with("不明") => name,
        _ => "",
    }
}

fn route_or_time(entry: &TransactionEntry) -> String {
    if let Some(time) = &entry.transaction_time {
        return time.clone();
    }
    let entry_station = clean_station(entry.entry_station.as_ref());
    let exit_station = clean_station(entry.exit_station.as_ref());
    match (entry_station.is_empty(), exit_station.is_empty()) {
        (false, false) => format!("{entry_station} → {exit_station}"),
        (false, true) => entry_station.to_string(),
        (true, false) => exit_station.to_string(),
        (true, true) => "—".to_string(),
    }
}

fn hhmm(hex_clock: &str) -> String {
    if hex_clock.len() >= 4 {
        format!("{}:{}", &hex_clock[0..2], &hex_clock[2..4])
    } else {
        "—".to_string()
    }
}

fn dash(value: &str) -> &str {
    if value.is_empty() { "—" } else { value }
}

// --------------------------------------------------------------------------- //
// Rendering                                                                   //
// --------------------------------------------------------------------------- //

/// Renders a [`CardData`] as a colored, aligned console report.
struct TextReport {
    palette: Palette,
    verbose: bool,
    lines: Vec<String>,
}

impl TextReport {
    fn new(palette: Palette, verbose: bool) -> Self {
        Self {
            palette,
            verbose,
            lines: Vec::new(),
        }
    }

    fn render(mut self, card: &CardData) -> String {
        self.banner("Suica カード情報");
        self.quick_summary(card);
        self.identification(card);
        self.issue_information(card);
        self.attribute_information(card);
        self.last_topup(card);
        if self.verbose {
            self.misc_information(card);
        }
        self.transaction_history(card);
        self.commuter_pass(card);
        self.gate_history(card);
        self.sf_gate(card);
        self.paid_ticket(card);
        self.lines.join("\n")
    }

    // -- building blocks --------------------------------------------------- //

    fn banner(&mut self, title: &str) {
        let inner = format!("  {title}  ");
        let bar = "━".repeat(display_width(&inner));
        self.lines.push(self.palette.cyan(&bar));
        let heading = self.palette.bold(&inner);
        self.lines.push(self.palette.cyan(&heading));
        self.lines.push(self.palette.cyan(&bar));
    }

    fn section(&mut self, title: &str) {
        self.lines.push(String::new());
        self.lines.push(self.palette.bold(title));
        self.lines
            .push(self.palette.dim(&"─".repeat(display_width(title))));
    }

    fn key_values(&mut self, pairs: &[(&str, String)]) {
        let width = pairs
            .iter()
            .map(|(label, _)| display_width(label))
            .max()
            .unwrap_or(0);
        for (label, value) in pairs {
            let label = self.palette.dim(&fit(label, width, Align::Left));
            self.lines.push(format!("  {label}  {value}"));
        }
    }

    fn table_header(&mut self, headers: &[&str], widths: &[usize]) {
        let cells: Vec<String> = headers
            .iter()
            .enumerate()
            .map(|(index, header)| match widths.get(index) {
                Some(&width) => {
                    let align = if matches!(*header, "No" | "差額" | "残高" | "金額") {
                        Align::Right
                    } else {
                        Align::Left
                    };
                    fit(header, width, align)
                }
                None => header.to_string(),
            })
            .collect();
        self.lines
            .push(format!("  {}", self.palette.dim(&cells.join("  "))));
    }

    fn empty_note(&mut self, note: &str) {
        self.lines.push(self.palette.dim(&format!("  {note}")));
    }

    // -- sections ---------------------------------------------------------- //

    fn quick_summary(&mut self, card: &CardData) {
        let balance = self
            .palette
            .green(&format_yen(i64::from(card.attribute.balance)));
        let balance = self.palette.bold(&balance);
        self.lines.push(String::new());
        let mut pairs = vec![
            ("残高", balance),
            ("カード種別", card.attribute.card_type.clone()),
            ("発行者", card.issue_primary.issuer_id.clone()),
            ("有効期限", card.issue_primary.expires_at.clone()),
        ];
        if card.issue_primary.collected {
            pairs.push(("状態", self.palette.red("取り込み済み（無効カード）")));
        }
        self.key_values(&pairs);
    }

    fn identification(&mut self, card: &CardData) {
        self.section("カード識別");
        self.key_values(&[
            ("IDm", card.system.idm_hex.clone()),
            ("PMm", card.system.pmm_hex.clone()),
            ("IDi", card.system.idi_display.clone()),
            ("PMi", card.system.pmi.clone()),
        ]);
    }

    fn issue_information(&mut self, card: &CardData) {
        let issue = &card.issue_primary;
        self.section("発行情報");

        let mut pairs = vec![
            ("所有者名", dash(&issue.owner_name).to_string()),
            ("生年月日", issue.owner_birthdate.clone()),
        ];
        if self.verbose {
            pairs.push(("電話番号(hex)", dash(&issue.owner_phone_hex).to_string()));
            pairs.push(("年齢コード", issue.owner_age_code.clone()));
        }
        pairs.extend([
            ("第二発行ID", issue.secondary_issue_id.clone()),
            ("発行者ID", issue.issuer_id.clone()),
            ("発行機器", issue.issued_by.clone()),
            ("発行駅", issue.issued_station.clone()),
            ("発行日", issue.issued_at.clone()),
            ("有効期限", issue.expires_at.clone()),
            ("デポジット額", format_yen(i64::from(issue.deposit))),
        ]);
        if issue.collected {
            pairs.push((
                "取り込み済み",
                self.palette.red("はい（無効カード）").to_string(),
            ));
        }
        self.key_values(&pairs);
    }

    fn attribute_information(&mut self, card: &CardData) {
        let attribute = &card.attribute;
        self.section("属性情報");

        let mut pairs = vec![
            ("カード種別", attribute.card_type.clone()),
            ("残高", format_yen(i64::from(attribute.balance))),
            (
                "取引通番",
                thousands(i64::from(attribute.transaction_number)),
            ),
        ];
        if self.verbose {
            pairs.push(("地域コード", format_region(attribute.region)));
        }
        self.key_values(&pairs);
    }

    fn last_topup(&mut self, card: &CardData) {
        let topup = &card.last_topup;
        self.section("最終チャージ情報");
        self.key_values(&[
            ("チャージ機器", topup.equipment.clone()),
            ("チャージ駅", topup.station.clone()),
            ("チャージ金額", format_yen(i64::from(topup.amount))),
        ]);
    }

    fn misc_information(&mut self, card: &CardData) {
        let misc = &card.unknown;
        self.section("その他情報（用途未確定）");
        self.key_values(&[
            ("不明な残高", format_yen(i64::from(misc.balance))),
            ("不明な日付", misc.date.clone()),
            (
                "不明な取引通番",
                thousands(i64::from(misc.transaction_number)),
            ),
        ]);
    }

    fn transaction_history(&mut self, card: &CardData) {
        let entries = &card.transaction_history;
        self.section(&format!("取引履歴（新しい順・{}件）", entries.len()));
        if entries.is_empty() {
            self.empty_note("（記録なし）");
            return;
        }

        let widths = [3, 10, 14, 9, 9];
        self.table_header(
            &["No", "日付", "種別", "差額", "残高", "経路 / 時刻"],
            &widths,
        );
        for entry in entries {
            let mut delta_cell = fit(&format_delta(entry.delta), widths[3], Align::Right);
            if entry.delta.is_some_and(|delta| delta > 0) {
                delta_cell = self.palette.green(&delta_cell);
            }
            let cells = [
                fit(&(entry.index + 1).to_string(), widths[0], Align::Right),
                fit(&entry.recorded_on, widths[1], Align::Left),
                fit(&entry.transaction_type, widths[2], Align::Left),
                delta_cell,
                fit(&yen_compact(entry.balance), widths[4], Align::Right),
                route_or_time(entry),
            ];
            self.lines.push(format!("  {}", cells.join("  ")));
        }
    }

    fn commuter_pass(&mut self, card: &CardData) {
        self.section("定期情報");
        if !card.has_commuter_pass() {
            self.empty_note("（定期券なし）");
            return;
        }

        let commuter = &card.commuter;
        let mut pairs = vec![(
            "区間",
            format!("{} → {}", commuter.start_station, commuter.end_station),
        )];

        let vias: Vec<&str> = [
            clean_station(Some(&commuter.via1_station)),
            clean_station(Some(&commuter.via2_station)),
        ]
        .into_iter()
        .filter(|station| !station.is_empty())
        .collect();
        if !vias.is_empty() {
            pairs.push(("経由", vias.join(" / ")));
        }

        pairs.push((
            "有効期間",
            format!("{} 〜 {}", commuter.valid_from, commuter.valid_to),
        ));
        pairs.push(("発行日", commuter.issued_at.clone()));
        self.key_values(&pairs);
    }

    fn gate_history(&mut self, card: &CardData) {
        let entries = &card.gate;
        self.section(&format!("改札入出場情報（{}件）", entries.len()));
        if entries.is_empty() {
            self.empty_note("（記録なし）");
            return;
        }

        let widths = [3, 17, 14, 9];
        self.table_header(&["No", "日時", "入出場種別", "金額", "駅"], &widths);
        for entry in entries {
            let timestamp = format!("{} {}", entry.date, entry.time);
            let cells = [
                fit(&(entry.index + 1).to_string(), widths[0], Align::Right),
                fit(timestamp.trim(), widths[1], Align::Left),
                fit(&entry.gate_in_out_type, widths[2], Align::Left),
                fit(&yen_compact(entry.amount), widths[3], Align::Right),
                entry.station.clone(),
            ];
            self.lines.push(format!("  {}", cells.join("  ")));
            if self.verbose {
                self.lines.push(self.palette.dim(&gate_detail(entry)));
            }
        }
    }

    fn sf_gate(&mut self, card: &CardData) {
        let sf = &card.sf_gate;
        self.section("SF改札入場情報");
        if !sf.has_record {
            self.empty_note("（記録なし）");
            return;
        }

        let mut pairs = vec![
            ("入場駅", sf.entry_station.clone()),
            ("中間改札入場駅", sf.intermediate_entry_station.clone()),
            (
                "中間改札入場",
                format!(
                    "{} {}",
                    sf.intermediate_entry_date,
                    hhmm(&sf.intermediate_entry_time)
                ),
            ),
            ("中間改札出場駅", sf.intermediate_exit_station.clone()),
            ("中間改札出場時刻", hhmm(&sf.intermediate_exit_time)),
        ];
        if self.verbose {
            pairs.push(("不明値1", sf.unknown_value1_hex.clone()));
            pairs.push(("不明値2", sf.unknown_value2_hex.clone()));
        }
        self.key_values(&pairs);
    }

    fn paid_ticket(&mut self, card: &CardData) {
        let entries = &card.paid_ticket;
        self.section(&format!("料金発券・改札情報（{}件）", entries.len()));
        if entries.is_empty() {
            let reason = card
                .paid_ticket_reason
                .as_deref()
                .unwrap_or("（記録なし）")
                .to_string();
            self.empty_note(&reason);
            return;
        }

        let widths = [3, 10, 9, 8];
        self.table_header(
            &["No", "有効期限", "金額", "発券時刻", "区間（発→着）"],
            &widths,
        );
        for entry in entries {
            let cells = [
                fit(&(entry.index + 1).to_string(), widths[0], Align::Right),
                fit(&entry.expires_at, widths[1], Align::Left),
                fit(&yen_compact(entry.amount), widths[2], Align::Right),
                fit(&entry.issued_time, widths[3], Align::Left),
                format!("{} → {}", entry.depart_station, entry.arrive_station),
            ];
            self.lines.push(format!("  {}", cells.join("  ")));
            if self.verbose {
                self.lines
                    .push(self.palette.dim(&paid_ticket_detail(entry)));
            }
        }
    }
}

fn gate_detail(entry: &GateEntry) -> String {
    format!(
        "       装置番号 {} / 中間処理 {} / 定期運賃 {} / 最寄定期駅 {}",
        entry.device_id_hex,
        entry.intermediate_gate_instruction_type,
        yen_compact(entry.commuter_pass_fee),
        entry.commuter_station,
    )
}

fn paid_ticket_detail(entry: &PaidTicketEntry) -> String {
    format!(
        "       発券種別 {} / 装置番号 {} / 改札実施 {} {}",
        entry.issue_type_hex, entry.device_id_hex, entry.checked_station, entry.checked_time,
    )
}

// --------------------------------------------------------------------------- //
// Entry point                                                                 //
// --------------------------------------------------------------------------- //

fn main() -> ExitCode {
    env_logger::init();
    let args = Args::parse();

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    let color_enabled = !args.no_color
        && !args.json
        && std::env::var_os("NO_COLOR").is_none()
        && std::io::stdout().is_terminal();
    let palette = Palette {
        enabled: color_enabled,
    };

    let service = CardDataService::new(StationCodeLookup::new());
    let server_url = resolve_server_url(args.server.as_deref());
    let mut client =
        AuthClient::new(&server_url).map_err(|error| format!("初期化に失敗しました: {error}"))?;

    let mut card_reader =
        reader::open().map_err(|error| format!("NFC リーダーを初期化できません: {error}"))?;
    let mut driver = SharedDriver::new(card_reader.driver_mut());

    if !args.json {
        eprintln!("カードをかざしてください。");
        let _ = std::io::stderr().flush();
    }

    // Poll until a card shows up; an idle reader is not an error.
    let mut card = loop {
        match CardSession::poll(&mut driver, SYSTEM_CODE) {
            Ok(Some(card)) => break card,
            Ok(None) => std::thread::sleep(reader::POLL_INTERVAL),
            Err(error) => return Err(format!("カードのポーリングに失敗しました: {error}")),
        }
    };

    eprintln!("カードを読み取っています…");
    let _ = std::io::stderr().flush();

    let data = service
        .collect(&mut client, &mut card, None)
        .map_err(|error| format!("カード情報の取得に失敗しました: {error}"))?;

    if args.json {
        let json = serde_json::to_string_pretty(&data)
            .map_err(|error| format!("JSON の生成に失敗しました: {error}"))?;
        println!("{json}");
    } else {
        println!("{}", TextReport::new(palette, args.verbose).render(&data));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_width_glyphs_count_as_two_columns() {
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("東京"), 4);
        assert_eq!(display_width("東京駅 A"), 8);
    }

    #[test]
    fn fitting_pads_and_truncates_to_exact_columns() {
        assert_eq!(display_width(&fit("abc", 6, Align::Left)), 6);
        assert_eq!(fit("abc", 6, Align::Right), "   abc");
        // Truncation leaves room for the ellipsis, which is itself one column.
        // Full-width glyphs can leave the result a column short of the target,
        // which the padding then makes up.
        let truncated = fit("東日本旅客鉄道", 8, Align::Left);
        assert_eq!(display_width(&truncated), 8);
        assert_eq!(truncated.trim_end(), "東日本…");
    }

    #[test]
    fn a_disabled_palette_emits_no_escape_codes() {
        let plain = Palette { enabled: false };
        assert_eq!(plain.green("x"), "x");
        let colored = Palette { enabled: true };
        assert!(colored.green("x").starts_with('\u{1b}'));
    }

    #[test]
    fn deltas_are_signed_and_absent_deltas_dash() {
        assert_eq!(format_delta(Some(1200)), "+1,200");
        assert_eq!(format_delta(Some(-330)), "-330");
        assert_eq!(format_delta(None), "—");
    }

    #[test]
    fn routes_drop_stations_the_dataset_could_not_name() {
        let base = TransactionEntry {
            index: 0,
            recorded_on: "2025-07-24".into(),
            recorded_by_code: 0x16,
            recorded_by: "自動改札機".into(),
            transaction_type_code: 0x01,
            transaction_type: "自動改札機出場".into(),
            pay_type_code: 0,
            pay_type: "現金/なし".into(),
            gate_instruction_type_code: 2,
            gate_instruction_type: "入場/出場".into(),
            transaction_time: None,
            entry_station: Some("東日本旅客鉄道 東海道線 東京".into()),
            exit_station: Some("不明 (線区コード: 0xFF, 駅順コード: 0xFF)".into()),
            balance: 1000,
            transaction_number: 5,
            delta: Some(-200),
        };
        assert_eq!(route_or_time(&base), "東日本旅客鉄道 東海道線 東京");

        let purchase = TransactionEntry {
            transaction_time: Some("12:34:30".into()),
            entry_station: None,
            exit_station: None,
            ..base.clone()
        };
        assert_eq!(route_or_time(&purchase), "12:34:30");

        let unknown_both = TransactionEntry {
            entry_station: Some("不明 (…)".into()),
            exit_station: Some("不明 (…)".into()),
            ..base
        };
        assert_eq!(route_or_time(&unknown_both), "—");
    }

    #[test]
    fn hex_clocks_render_as_wall_time() {
        assert_eq!(hhmm("1234"), "12:34");
        assert_eq!(hhmm("12"), "—");
    }
}
