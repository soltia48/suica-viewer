//! Station name resolution from the bundled `station_codes.csv`.
//!
//! The dataset is small enough (~7k rows) to embed in the binary and index once
//! at startup, which keeps the lookup a hash probe per station rather than a
//! file scan.

use std::collections::HashMap;

/// The dataset ships inside the binary so a single executable is self-contained.
const STATION_CODES_CSV: &str = include_str!("../assets/station_codes.csv");

/// Company / line / station names for one line-and-order code pair.
#[derive(Debug, Clone)]
pub struct StationInfo {
    pub area_code: u8,
    pub line_code: u8,
    pub station_code: u8,
    pub company_name: String,
    pub line_name: String,
    pub station_name: String,
    pub notes: String,
}

/// Index over the station code dataset, keyed by `(線区コード, 駅順コード, 地域コード)`.
pub struct StationCodeLookup {
    stations: HashMap<(u8, u8, u8), StationInfo>,
}

impl StationCodeLookup {
    /// Builds the index from the embedded dataset.
    ///
    /// Rows whose codes are not parseable hex are skipped: a malformed line
    /// should cost one station name, not the whole lookup.
    pub fn new() -> Self {
        Self::from_csv(STATION_CODES_CSV)
    }

    pub fn from_csv(data: &str) -> Self {
        let mut stations = HashMap::new();
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .from_reader(data.as_bytes());

        for record in reader.records().flatten() {
            let field = |index: usize| record.get(index).unwrap_or("").trim();
            let (Some(area_code), Some(line_code), Some(station_code)) = (
                parse_hex_u8(field(0)),
                parse_hex_u8(field(1)),
                parse_hex_u8(field(2)),
            ) else {
                continue;
            };

            // Later rows win, matching the dict-assignment order of the dataset
            // as it was originally indexed.
            stations.insert(
                (line_code, station_code, area_code),
                StationInfo {
                    area_code,
                    line_code,
                    station_code,
                    company_name: field(3).to_string(),
                    line_name: field(4).to_string(),
                    station_name: field(5).to_string(),
                    notes: field(6).to_string(),
                },
            );
        }

        Self { stations }
    }

    /// Looks up one station by line code and station order code.
    pub fn get(&self, line_code: u8, station_order: u8, area_code: u8) -> Option<&StationInfo> {
        self.stations.get(&(line_code, station_order, area_code))
    }

    /// Number of indexed stations.
    pub fn len(&self) -> usize {
        self.stations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.stations.is_empty()
    }
}

impl Default for StationCodeLookup {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_hex_u8(value: &str) -> Option<u8> {
    u8::from_str_radix(value.trim(), 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_dataset_indexes_and_resolves_a_known_station() {
        let lookup = StationCodeLookup::new();
        assert!(lookup.len() > 5_000, "dataset looks truncated");

        // 線区 0x01 / 駅順 0x01 / 地域 0x00 = 東日本旅客鉄道 東海道線 東京
        let tokyo = lookup.get(0x01, 0x01, 0x00).expect("東京 should resolve");
        assert_eq!(tokyo.company_name, "東日本旅客鉄道");
        assert_eq!(tokyo.station_name, "東京");
    }

    #[test]
    fn quoted_fields_containing_commas_do_not_shift_columns() {
        // 大阪市高速電気軌道 梅田 carries a quoted 備考 with an embedded comma.
        let lookup = StationCodeLookup::new();
        let umeda = lookup.get(0x81, 0x1C, 0x02).expect("梅田 should resolve");
        assert_eq!(umeda.company_name, "大阪市高速電気軌道");
        assert_eq!(umeda.station_name, "梅田");
        assert!(umeda.notes.contains(','), "notes should keep the comma");
    }

    #[test]
    fn area_code_differentiates_stations_with_identical_line_and_station_codes() {
        let lookup = StationCodeLookup::new();

        // 線区 0x82 / 駅順 0x22 / 地域 0x01 = 矢場町
        let yabacho = lookup.get(0x82, 0x22, 0x01).expect("矢場町 should resolve");
        assert_eq!(yabacho.company_name, "名古屋市交通局");
        assert_eq!(yabacho.station_name, "矢場町");

        // 線区 0x82 / 駅順 0x22 / 地域 0x02 = 天満橋
        let temmabashi = lookup.get(0x82, 0x22, 0x02).expect("天満橋 should resolve");
        assert_eq!(temmabashi.company_name, "大阪市高速電気軌道");
        assert_eq!(temmabashi.station_name, "天満橋");
    }

    #[test]
    fn unknown_codes_resolve_to_none() {
        let lookup = StationCodeLookup::new();
        assert!(lookup.get(0xFF, 0xFF, 0xFF).is_none());
    }

    #[test]
    fn malformed_rows_are_skipped_without_dropping_good_ones() {
        let lookup = StationCodeLookup::from_csv(
            "地区,線区,駅順,会社名,線区名,駅名,備考\n\
             0,ZZ,1,壊れた会社,壊れた線,壊れた駅,\n\
             0,2,3,良い会社,良い線,良い駅,\n",
        );
        assert_eq!(lookup.len(), 1);
        assert_eq!(lookup.get(0x02, 0x03, 0x00).unwrap().station_name, "良い駅");
    }
}
