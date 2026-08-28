//! Bus company name resolution from the bundled `bus_company_codes.csv`.

use std::collections::HashMap;

/// The dataset ships inside the binary so a single executable is self-contained.
const BUS_COMPANY_CODES_CSV: &str = include_str!("../assets/bus_company_codes.csv");

#[derive(Debug, Clone)]
pub struct BusCompanyInfo {
    pub company_code: u16,
    pub company_name: String,
    pub notes: String,
}

pub struct BusCompanyCodeLookup {
    buscompanies: HashMap<u16, BusCompanyInfo>,
}

impl BusCompanyCodeLookup {
    /// Builds the index from the embedded dataset.
    ///
    /// Rows whose codes are not parseable hex are skipped: a malformed line
    /// should cost one company name, not the whole lookup.
    pub fn new() -> Self {
        Self::from_csv(BUS_COMPANY_CODES_CSV)
    }

    pub fn from_csv(data: &str) -> Self {
        let mut buscompanies = HashMap::new();
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .from_reader(data.as_bytes());

        for record in reader.records().flatten() {
            let field = |index: usize| record.get(index).unwrap_or("").trim();
            let Some(company_code) = parse_hex_u16(field(0)) else {
                continue;
            };

            // Later rows win, matching the dict-assignment order of the dataset
            // as it was originally indexed.
            buscompanies.insert(company_code, 
                BusCompanyInfo {
                    company_code,
                    company_name: field(1).to_string(),
                    notes: field(2).to_string(),
                },
            );
        }

        Self { buscompanies }
    }

    /// Looks up one company by company code.
    pub fn get(&self, company_code: u16) -> Option<&BusCompanyInfo> {
        self.buscompanies.get(&company_code)
    }

    /// Number of indexed companies.
    pub fn len(&self) -> usize {
        self.buscompanies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buscompanies.is_empty()
    }
}

impl Default for BusCompanyCodeLookup {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_hex_u16(value: &str) -> Option<u16> {
    u16::from_str_radix(value.trim(), 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_dataset_indexes_and_resolves_a_known_company() {
        let lookup = BusCompanyCodeLookup::new();

        // 事業者コード 0x0365 = 名古屋市交通局
        let nagoya_city = lookup.get(0x0365).expect("名古屋市交通局 should resolve");
        assert_eq!(nagoya_city.company_name, "名古屋市交通局");
    }

    #[test]
    fn unknown_codes_resolve_to_none() {
        let lookup = BusCompanyCodeLookup::new();
        assert!(lookup.get(0xFFFF).is_none());
    }

    #[test]
    fn malformed_rows_are_skipped_without_dropping_good_ones() {
        let lookup = BusCompanyCodeLookup::from_csv(
            "事業者コード,会社名,備考\n\
            ZZ,壊れた会社,\n\
            0,良い会社,\n",
        );
        assert_eq!(lookup.len(), 1);
        assert_eq!(lookup.get(0).unwrap().company_name, "良い会社");
    }
}
