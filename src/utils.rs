//! Lookup tables and value formatters shared by the card decoder and both front
//! ends.
//!
//! Every label here is what ends up in the CLI report and in the JSON the web
//! UI renders, so the wording is kept verbatim from the tables the FeliCa
//! community documented.

use chrono::Datelike;

use crate::station_codes::StationCodeLookup;

/// System code of the transit (Suica) system on a FeliCa Standard card.
pub const SYSTEM_CODE: u16 = 0x0003;

fn equipment_type(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "未定義",
        0x03 => "のりこし精算機",
        0x04 => "携帯端末",
        0x05 => "バス等車載機",
        0x07 => "カード発売機",
        0x08 => "自動券売機",
        0x09 => "SMART ICOCA クイックチャージ機?",
        0x12 => "自動券売機(東京モノレール)",
        0x14 => "駅務機器(PASMO発行機?)",
        0x15 => "定期券発売機",
        0x16 => "自動改札機",
        0x17 => "簡易改札機",
        0x18 => "駅務機器(発行機?)",
        0x19 => "窓口処理機(みどりの窓口)",
        0x1A => "窓口処理機(有人改札)",
        0x1B => "モバイルFeliCa",
        0x1C => "入場券券売機",
        0x1D => "他社乗換自動改札機",
        0x1F => "入金機",
        0x20 => "発行機?(モノレール)",
        0x22 => "簡易改札機(ことでん)",
        0x34 => "カード発売機(せたまる?)",
        0x35 => "バス等車載機(せたまる車内入金機?)",
        0x36 => "バス等車載機(車内簡易改札機)",
        0x46 => "ビューアルッテ端末",
        0xC7 | 0xC8 => "物販端末",
        _ => return None,
    })
}

fn transaction_type(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "未定義",
        0x01 => "自動改札機出場",
        0x02 => "SFチャージ",
        0x03 => "きっぷ購入",
        0x04 => "磁気券精算",
        0x05 => "乗越精算",
        0x06 => "窓口出場",
        0x07 => "新規",
        0x08 => "控除",
        0x0D => "バス等均一運賃",
        0x0F => "バス等",
        0x11 => "再発行?",
        0x13 => "料金出場",
        0x14 => "オートチャージ",
        0x1F => "バス等チャージ",
        0x46 => "物販",
        0x48 => "ポイントチャージ",
        0x4B => "入場・物販",
        _ => return None,
    })
}

fn pay_type(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "現金/なし",
        0x02 => "VIEW",
        0x0B => "PiTaPa",
        0x0D => "オートチャージ対応PASMO",
        0x3F => "モバイルSuica(VIEW決済以外)",
        _ => return None,
    })
}

fn gate_instruction_type(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "未定義",
        0x01 => "入場",
        0x02 => "入場/出場",
        0x03 => "定期入場/出場",
        0x04 => "入場/定期出場",
        0x0E => "窓口出場",
        0x0F => "入場/出場(バス等)",
        0x12 => "料金定期入場/料金出場",
        0x17 => "入場/出場(乗継割引)",
        0x21 => "入場/出場(バス等乗継割引)",
        _ => return None,
    })
}

fn gate_in_out_type(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "精算出場",
        0x01 => "精算出場(プリペイドカード併用?)",
        0x20 => "出場",
        0x21 => "駅務機器出場",
        0x22 => "割引出場",
        0x24 => "割引出場?",
        0x40 => "定期出場",
        0x80 => "均一区間入場?",
        0xA0 => "入場",
        0xA2 => "割引入場?",
        0xC0 => "定期入場",
        _ => return None,
    })
}

fn intermediate_gate_instruction_type(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "未定義",
        0x04 => "乗継割引?",
        0x08 => "電車バス乗継割引?",
        0x40 => "新幹線中間改札?",
        _ => return None,
    })
}

/// Issuer company name and two-letter identifier for a known issuer ID.
fn issuer_id_info(issuer_id_hex: &str) -> Option<(&'static str, &'static str)> {
    Some(match issuer_id_hex {
        "0102" => ("北海道旅客鉄道株式会社", "JH"),
        "0103" => ("東日本旅客鉄道株式会社", "JE"),
        "0104" => ("東海旅客鉄道株式会社", "JC"),
        "0105" => ("西日本旅客鉄道株式会社", "JW"),
        "0107" => ("九州旅客鉄道株式会社", "JK"),
        "0252" => ("株式会社パスモ", "PB"),
        "0387" => ("株式会社名古屋交通開発機構・株式会社エムアイシー", "TP"),
        "04AD" => ("株式会社スルッとKANSAI", "SU"),
        "05D5" => ("株式会社ニモカ", "NR"),
        "05D7" => ("福岡市交通局", "FC"),
        _ => return None,
    })
}

fn labelled(value: Option<&'static str>, code: u8, unknown_label: &str) -> String {
    match value {
        Some(label) => label.to_string(),
        None => format!("不明な{unknown_label} (0x{code:02X})"),
    }
}

pub fn equipment_type_to_str(code: u8) -> String {
    labelled(equipment_type(code), code, "機器種別")
}

pub fn transaction_type_to_str(code: u8) -> String {
    labelled(transaction_type(code), code, "取引種別")
}

pub fn pay_type_to_str(code: u8) -> String {
    labelled(pay_type(code), code, "支払種別")
}

pub fn gate_instruction_type_to_str(code: u8) -> String {
    labelled(gate_instruction_type(code), code, "改札処理種別")
}

pub fn gate_in_out_type_to_str(code: u8) -> String {
    labelled(gate_in_out_type(code), code, "改札入出場種別")
}

pub fn intermediate_gate_instruction_type_to_str(code: u8) -> String {
    labelled(
        intermediate_gate_instruction_type(code),
        code,
        "中間改札処理種別",
    )
}

/// Splits the packed on-card date into `(year offset, month, day)`.
pub fn int_to_date(value: u16) -> (u16, u16, u16) {
    (value >> 9, (value >> 5) & 0x0F, value & 0x1F)
}

/// Splits the packed on-card time into `(hour, minute, second)`.
pub fn int_to_time(value: u16) -> (u16, u16, u16) {
    (value >> 11, (value >> 5) & 0x3F, (value & 0x1F) * 2)
}

/// Formats a packed card date as `YYYY-MM-DD`.
///
/// Empty date slots come back as all-zero. Year 0 / month 0 / day 0 is not a
/// real date, so it renders as a dash instead of a misleading "2000-00-00".
pub fn format_date(value: u16) -> String {
    if value == 0 {
        return "—".to_string();
    }
    let (year, month, day) = int_to_date(value);
    format!("{:04}-{:02}-{:02}", 2000 + year, month, day)
}

/// Formats a birth date, inferring the century of its two-digit year.
///
/// The on-card year is effectively two digits, so 1999 and 2099 are
/// indistinguishable from the raw value. Every other card date is card-era
/// (2001 onward), so [`format_date`]'s plain 2000-based reading is correct for
/// them. A birth date, however, can predate 2000, so pick the most recent
/// century that does not put the date in the future (a birth date cannot be
/// later than today). Example: year `99` reads as 2099 → not yet reached →
/// 1999.
pub fn format_birth_date(value: u16) -> String {
    format_birth_date_with_reference(value, chrono::Local::now().year())
}

pub fn format_birth_date_with_reference(value: u16, reference_year: i32) -> String {
    if value == 0 {
        return "—".to_string();
    }
    let (year, month, day) = int_to_date(value);
    let mut full_year = 2000 + i32::from(year);
    if full_year > reference_year {
        full_year -= 100;
    }
    format!("{full_year:04}-{month:02}-{day:02}")
}

/// Formats a packed card time as `HH:MM:SS`.
pub fn format_time(value: u16) -> String {
    let (hour, minute, second) = int_to_time(value);
    format!("{hour:02}:{minute:02}:{second:02}")
}

/// Renders an integer with `,` thousands separators.
pub fn thousands(value: i64) -> String {
    let negative = value < 0;
    let digits = value.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if negative {
        out.push('-');
    }
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Formats an integer amount as yen with thousands separators.
pub fn format_yen(value: i64) -> String {
    format!("{} 円", thousands(value))
}

/// Renders the attribute region code as both decimal and hex.
/// Resolves a line/station code pair to `会社名 線区名 駅名`.
pub fn format_station(lookup: &StationCodeLookup, line_code: u8, station_order: u8) -> String {
    match lookup.get(line_code, station_order) {
        Some(station) => format!(
            "{} {} {}",
            station.company_name, station.line_name, station.station_name
        ),
        None => format!("不明 (線区コード: 0x{line_code:02X}, 駅順コード: 0x{station_order:02X})"),
    }
}

/// Renders an issuer ID as `HEX (会社名 / 識別子)` when the issuer is known.
pub fn issuer_id_to_str(issuer_id_hex: &str) -> String {
    let key = issuer_id_hex.to_uppercase();
    match issuer_id_info(&key) {
        Some((company, identifier)) => format!("{key} ({company} / {identifier})"),
        None => key,
    }
}

/// Converts an 8-byte IDi to its printed form.
///
/// Shorter inputs cannot carry the packed date and serial, so they fall back to
/// plain uppercase hex rather than producing a bogus identifier.
pub fn idi_bytes_to_str(idi: &[u8]) -> String {
    if idi.len() < 8 {
        return hex::encode_upper(idi);
    }

    let issuer_hex = hex::encode_upper(&idi[0..2]);
    let remainder = hex::encode_upper(&idi[2..4]);
    let head = match issuer_id_info(&issuer_hex) {
        Some((_, identifier)) => format!("{identifier}{remainder}"),
        None => format!("{issuer_hex}{remainder}"),
    };

    let packed = u16::from_be_bytes([idi[4], idi[5]]);
    let year = (packed >> 9) & 0x3F;
    let month = (packed >> 5) & 0x0F;
    let day = packed & 0x1F;
    let date_part = format!("{:02}{:02}{:02}", year % 100, month, day);

    let tail = format!("{:05}", u16::from_be_bytes([idi[6], idi[7]]));

    format!("{head}{date_part}{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_codes_fall_back_to_a_labelled_hex_value() {
        assert_eq!(equipment_type_to_str(0x16), "自動改札機");
        assert_eq!(equipment_type_to_str(0xFE), "不明な機器種別 (0xFE)");
        assert_eq!(transaction_type_to_str(0x99), "不明な取引種別 (0x99)");
    }

    #[test]
    fn zero_dates_render_as_a_dash() {
        assert_eq!(format_date(0), "—");
        assert_eq!(format_birth_date_with_reference(0, 2026), "—");
    }

    #[test]
    fn packed_dates_and_times_unpack() {
        // 2025-07-24 => year 25, month 7, day 24
        let packed = (25 << 9) | (7 << 5) | 24;
        assert_eq!(format_date(packed), "2025-07-24");
        // 23:59:58 => hour 23, minute 59, second 29*2
        let clock = (23 << 11) | (59 << 5) | 29;
        assert_eq!(format_time(clock), "23:59:58");
    }

    #[test]
    fn birth_dates_pick_the_most_recent_non_future_century() {
        let packed_99 = (99 << 9) | (5 << 5) | 3;
        assert_eq!(
            format_birth_date_with_reference(packed_99, 2026),
            "1999-05-03"
        );
        let packed_05 = (5 << 9) | (5 << 5) | 3;
        assert_eq!(
            format_birth_date_with_reference(packed_05, 2026),
            "2005-05-03"
        );
    }

    #[test]
    fn amounts_get_thousands_separators() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(thousands(-1_234), "-1,234");
        assert_eq!(format_yen(2_530), "2,530 円");
    }

    #[test]
    fn issuer_ids_resolve_to_company_names() {
        assert_eq!(
            issuer_id_to_str("0103"),
            "0103 (東日本旅客鉄道株式会社 / JE)"
        );
        assert_eq!(issuer_id_to_str("abcd"), "ABCD");
    }

    #[test]
    fn idi_renders_issuer_prefix_date_and_serial() {
        // Issuer 0103 (JE), remainder 0201, date 2025-07-24, serial 42.
        let packed_date = (25u16 << 9) | (7 << 5) | 24;
        let mut idi = vec![0x01, 0x03, 0x02, 0x01];
        idi.extend_from_slice(&packed_date.to_be_bytes());
        idi.extend_from_slice(&42u16.to_be_bytes());
        assert_eq!(idi_bytes_to_str(&idi), "JE0201250724".to_string() + "00042");
        assert_eq!(idi_bytes_to_str(&[0x01, 0x02]), "0102");
    }
}
