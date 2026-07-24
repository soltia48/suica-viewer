//! Reads the transit card's service blocks and decodes them into [`CardData`].
//!
//! Every field name and label produced here is part of the JSON contract the
//! web UI and `--json` consumers read, so the shape is deliberately flat and
//! stable.

use encoding_rs::SHIFT_JIS;
use serde::{Deserialize, Serialize};

use crate::auth_client::{AuthClient, AuthError};
use crate::card::CardSession;
use crate::station_codes::StationCodeLookup;
use crate::utils::{
    SYSTEM_CODE, card_type_label, equipment_type_to_str, format_birth_date, format_date,
    format_station, format_time, gate_in_out_type_to_str, gate_instruction_type_to_str,
    idi_bytes_to_str, intermediate_gate_instruction_type_to_str, issuer_id_to_str, pay_type_to_str,
    transaction_type_to_str,
};

/// Area nodes covered by the authentication.
pub const AREA_NODE_IDS: [u16; 5] = [0x0000, 0x0040, 0x0800, 0x0FC0, 0x1000];

/// Service nodes every transit card carries.
pub const SERVICE_NODE_IDS: [u16; 9] = [
    0x0048, 0x0088, 0x0810, 0x08C8, 0x090C, 0x1008, 0x1048, 0x108C, 0x10C8,
];

/// Paid-ticket / express-gate service (料金発券・改札情報). Not present on every
/// card, and reading it needs its own key, so it is probed and authenticated
/// only when the card actually carries it.
pub const PAID_TICKET_SERVICE_NODE_ID: u16 = 0x1848;

const READ_COMMAND_CODE: u8 = 0x14;
const DATA_BLOCK_SIZE: usize = 16;
const MAX_BLOCKS_PER_REQUEST: usize = 9;

/// Purchase (物販) transactions store a clock instead of entry/exit stations.
const PURCHASE_TRANSACTION_TYPE: u8 = 0x46;

type Block = [u8; DATA_BLOCK_SIZE];

#[derive(Debug, thiserror::Error)]
pub enum CardDataError {
    #[error("{0}")]
    Auth(#[from] AuthError),
    #[error("{0}")]
    Decode(String),
}

impl CardDataError {
    fn decode(message: impl Into<String>) -> Self {
        Self::Decode(message.into())
    }
}

type Result<T> = std::result::Result<T, CardDataError>;

/// Progress reporting, in percent, for front ends that show a bar.
pub type ProgressCallback<'a> = &'a mut dyn FnMut(f32);

// --------------------------------------------------------------------------- //
// Serialized shape                                                            //
// --------------------------------------------------------------------------- //

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub idm_hex: String,
    pub pmm_hex: String,
    pub idi_hex: String,
    pub idi_display: String,
    pub pmi: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuePrimary {
    pub owner_name: String,
    pub secondary_issue_id: String,
    pub owner_phone_hex: String,
    pub owner_age_code: String,
    pub owner_birthdate: String,
    pub deposit: u16,
    pub issuer_id: String,
    pub issuer_id_hex: String,
    pub issued_by_code: u8,
    pub issued_by: String,
    pub issued_station: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub card_type_code: u8,
    pub card_type: String,
    pub region: u8,
    pub balance: u16,
    pub transaction_number: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastTopup {
    pub equipment_code: u8,
    pub equipment: String,
    pub station: String,
    pub amount: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownInfo {
    pub balance: u16,
    pub date: String,
    pub transaction_number: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionEntry {
    pub index: usize,
    pub recorded_on: String,
    pub recorded_by_code: u8,
    pub recorded_by: String,
    pub transaction_type_code: u8,
    pub transaction_type: String,
    pub pay_type_code: u8,
    pub pay_type: String,
    pub gate_instruction_type_code: u8,
    pub gate_instruction_type: String,
    /// Set for purchases, which record a clock rather than a route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_station: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_station: Option<String>,
    pub balance: u16,
    pub transaction_number: u16,
    /// Balance change this transaction caused; `None` for the oldest entry,
    /// which has no predecessor on the card to compare against.
    pub delta: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commuter {
    pub valid_from: String,
    pub valid_to: String,
    pub start_station: String,
    pub end_station: String,
    pub via1_station: String,
    pub via2_station: String,
    pub issued_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateEntry {
    pub index: usize,
    pub date: String,
    pub time: String,
    pub gate_in_out_type_code: u8,
    pub gate_in_out_type: String,
    pub intermediate_gate_instruction_type_code: u8,
    pub intermediate_gate_instruction_type: String,
    pub station: String,
    pub device_id_hex: String,
    pub amount: u16,
    pub commuter_pass_fee: u16,
    pub commuter_station: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SfGate {
    pub has_record: bool,
    pub entry_station: String,
    pub intermediate_entry_date: String,
    pub intermediate_entry_time: String,
    pub intermediate_entry_station: String,
    pub unknown_value1_hex: String,
    pub intermediate_exit_time: String,
    pub intermediate_exit_station: String,
    pub unknown_value2_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaidTicketEntry {
    pub index: usize,
    pub depart_station: String,
    pub arrive_station: String,
    pub expires_at: String,
    pub issued_time: String,
    pub issue_type_hex: String,
    /// Yen. The on-card byte stores the amount divided by ten.
    pub amount: u16,
    pub device_id_hex: String,
    pub checked_station: String,
    pub checked_time: String,
}

/// Everything read off one card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardData {
    pub system: SystemInfo,
    pub issue_primary: IssuePrimary,
    pub attribute: Attribute,
    pub last_topup: LastTopup,
    pub unknown: UnknownInfo,
    pub transaction_history: Vec<TransactionEntry>,
    pub commuter: Commuter,
    pub gate: Vec<GateEntry>,
    pub sf_gate: SfGate,
    #[serde(default)]
    pub paid_ticket: Vec<PaidTicketEntry>,
    #[serde(default)]
    pub paid_ticket_available: bool,
    #[serde(default)]
    pub paid_ticket_reason: Option<String>,
}

impl CardData {
    /// True when the card carries a usable commuter pass record.
    pub fn has_commuter_pass(&self) -> bool {
        !matches!(self.commuter.valid_from.as_str(), "" | "—")
    }
}

// --------------------------------------------------------------------------- //
// Encrypted block reader                                                      //
// --------------------------------------------------------------------------- //

/// Issues Read commands through the auth server and returns plain blocks.
struct RemoteBlockReader<'client, 'card, 'driver> {
    client: &'client mut AuthClient,
    card: &'card mut CardSession<'driver>,
}

impl RemoteBlockReader<'_, '_, '_> {
    /// Reads `count` consecutive blocks starting at 0 from `service_index`.
    fn read_blocks(&mut self, service_index: u8, count: usize) -> Result<Vec<Block>> {
        let mut blocks = Vec::with_capacity(count);
        for chunk_start in (0..count).step_by(MAX_BLOCKS_PER_REQUEST) {
            let chunk_end = (chunk_start + MAX_BLOCKS_PER_REQUEST).min(count);
            let elements: Vec<u8> = (chunk_start..chunk_end)
                .flat_map(|block| [0x80 | service_index, block as u8])
                .collect();
            blocks.extend(self.read_elements(chunk_end - chunk_start, &elements)?);
        }
        Ok(blocks)
    }

    fn read_elements(&mut self, expected: usize, elements: &[u8]) -> Result<Vec<Block>> {
        let mut payload = Vec::with_capacity(elements.len() + 1);
        payload.push(expected as u8);
        payload.extend_from_slice(elements);

        let response = self
            .client
            .encryption_exchange(self.card, READ_COMMAND_CODE, &payload)?;

        if response.len() < 3 {
            return Err(CardDataError::decode(
                "リモートサーバーからの応答が不正です。",
            ));
        }
        let (status1, status2) = (response[0], response[1]);
        if status1 != 0x00 {
            let status = (u16::from(status1) << 8) | u16::from(status2);
            return Err(CardDataError::decode(format!(
                "カードがエラーを返しました: 0x{status:04X}"
            )));
        }
        if usize::from(response[2]) != expected {
            return Err(CardDataError::decode("取得したブロック数が一致しません。"));
        }

        let data = &response[3..];
        if data.len() < expected * DATA_BLOCK_SIZE {
            return Err(CardDataError::decode("ブロックデータの長さが不正です。"));
        }

        Ok(data
            .chunks_exact(DATA_BLOCK_SIZE)
            .take(expected)
            .map(|chunk| {
                let mut block = [0u8; DATA_BLOCK_SIZE];
                block.copy_from_slice(chunk);
                block
            })
            .collect())
    }
}

// --------------------------------------------------------------------------- //
// Block decoding                                                              //
// --------------------------------------------------------------------------- //

fn be16(block: &Block, offset: usize) -> u16 {
    u16::from_be_bytes([block[offset], block[offset + 1]])
}

fn le16(block: &Block, offset: usize) -> u16 {
    u16::from_le_bytes([block[offset], block[offset + 1]])
}

/// Decodes a Shift_JIS owner name, dropping the padding the card writes.
///
/// The field is fixed-width, so it arrives padded with spaces or NULs; both
/// would otherwise end up in the JSON and be rendered by the UI.
fn decode_owner_name(block: &Block) -> String {
    let (decoded, _, _) = SHIFT_JIS.decode(block);
    decoded
        .trim_end_matches(|ch: char| ch == '\0' || ch.is_whitespace())
        .to_string()
}

fn require<T>(blocks: &[T], needed: usize, section: &str) -> Result<()> {
    if blocks.len() < needed {
        return Err(CardDataError::decode(format!(
            "{section}のブロックが不足しています（{}/{needed}）。",
            blocks.len()
        )));
    }
    Ok(())
}

/// Decodes the raw service blocks into the structured card sections.
struct Decoder<'a> {
    stations: &'a StationCodeLookup,
}

impl Decoder<'_> {
    fn station(&self, line_code: u8, station_order: u8) -> String {
        format_station(self.stations, line_code, station_order)
    }

    fn issue_primary(&self, blocks: &[Block]) -> Result<IssuePrimary> {
        require(blocks, 4, "発行情報")?;
        let (owner, personal, secondary_idi, metadata) =
            (&blocks[0], &blocks[1], &blocks[2], &blocks[3]);

        let issuer_id_hex = hex::encode_upper(&metadata[0..2]);
        let issued_by_code = metadata[2];

        Ok(IssuePrimary {
            owner_name: decode_owner_name(owner),
            secondary_issue_id: idi_bytes_to_str(secondary_idi),
            owner_phone_hex: hex::encode_upper(&personal[0..8])
                .trim_end_matches('F')
                .to_string(),
            owner_age_code: hex::encode_upper(&personal[8..9]),
            owner_birthdate: format_birth_date(be16(personal, 9)),
            deposit: le16(personal, 12),
            issuer_id: issuer_id_to_str(&issuer_id_hex),
            issuer_id_hex,
            issued_by_code,
            issued_by: equipment_type_to_str(issued_by_code),
            issued_station: self.station(metadata[3], metadata[4]),
            issued_at: format_date(be16(metadata, 7)),
            expires_at: format_date(be16(metadata, 14)),
        })
    }

    fn attribute(&self, blocks: &[Block]) -> Result<Attribute> {
        require(blocks, 1, "属性情報")?;
        let block = &blocks[0];
        let card_type_code = block[8] >> 4;

        Ok(Attribute {
            card_type_code,
            card_type: card_type_label(card_type_code).to_string(),
            region: block[8] & 0x0F,
            balance: le16(block, 11),
            transaction_number: be16(block, 14),
        })
    }

    fn unknown(&self, blocks: &[Block]) -> Result<UnknownInfo> {
        require(blocks, 1, "その他情報")?;
        let block = &blocks[0];

        Ok(UnknownInfo {
            balance: le16(block, 0),
            date: format_date(be16(block, 8)),
            transaction_number: be16(block, 14),
        })
    }

    fn last_topup(&self, blocks: &[Block]) -> Result<LastTopup> {
        require(blocks, 1, "最終チャージ情報")?;
        let block = &blocks[0];
        let equipment_code = block[0];

        Ok(LastTopup {
            equipment_code,
            equipment: equipment_type_to_str(equipment_code),
            station: self.station(block[1], block[2]),
            amount: le16(block, 5),
        })
    }

    fn transaction_history(&self, blocks: &[Block]) -> Vec<TransactionEntry> {
        let mut entries = Vec::new();

        for (index, block) in blocks.iter().enumerate() {
            let recorded_by_code = block[0];
            // Unwritten slots read back as zero; everything past the first one
            // is empty too, so the history ends here.
            if recorded_by_code == 0x00 {
                break;
            }

            let transaction_type_code = block[1] & 0x7F;
            let pay_type_code = block[2];
            let gate_instruction_type_code = block[3];

            let is_purchase = transaction_type_code == PURCHASE_TRANSACTION_TYPE;
            let (transaction_time, entry_station, exit_station) = if is_purchase {
                (Some(format_time(be16(block, 6))), None, None)
            } else {
                (
                    None,
                    Some(self.station(block[6], block[7])),
                    Some(self.station(block[8], block[9])),
                )
            };

            entries.push(TransactionEntry {
                index,
                recorded_on: format_date(be16(block, 4)),
                recorded_by_code,
                recorded_by: equipment_type_to_str(recorded_by_code),
                transaction_type_code,
                transaction_type: transaction_type_to_str(transaction_type_code),
                pay_type_code,
                pay_type: pay_type_to_str(pay_type_code),
                gate_instruction_type_code,
                gate_instruction_type: gate_instruction_type_to_str(gate_instruction_type_code),
                transaction_time,
                entry_station,
                exit_station,
                balance: le16(block, 10),
                transaction_number: be16(block, 13),
                delta: None,
            });
        }

        annotate_balance_deltas(&mut entries);
        entries
    }

    fn commuter(&self, blocks: &[Block]) -> Result<Commuter> {
        require(blocks, 3, "定期情報")?;
        let (primary, supplemental) = (&blocks[0], &blocks[2]);

        Ok(Commuter {
            valid_from: format_date(be16(primary, 0)),
            valid_to: format_date(be16(primary, 2)),
            start_station: self.station(primary[8], primary[9]),
            end_station: self.station(primary[10], primary[11]),
            via1_station: self.station(primary[12], primary[13]),
            via2_station: self.station(primary[14], primary[15]),
            issued_at: format_date(be16(supplemental, 5)),
        })
    }

    fn gate(&self, blocks: &[Block]) -> Vec<GateEntry> {
        blocks
            .iter()
            .enumerate()
            // Unused gate slots come back zero-filled; skipping them keeps
            // phantom rows out of both front ends.
            .filter(|(_, block)| block.iter().any(|&byte| byte != 0))
            .map(|(index, block)| {
                let time_hex = hex::encode_upper(&block[8..10]);
                GateEntry {
                    index,
                    date: format_date(be16(block, 6)),
                    time: format!("{}:{}", &time_hex[0..2], &time_hex[2..4]),
                    gate_in_out_type_code: block[0],
                    gate_in_out_type: gate_in_out_type_to_str(block[0]),
                    intermediate_gate_instruction_type_code: block[1],
                    intermediate_gate_instruction_type: intermediate_gate_instruction_type_to_str(
                        block[1],
                    ),
                    station: self.station(block[2], block[3]),
                    device_id_hex: hex::encode_upper(&block[4..6]),
                    amount: le16(block, 10),
                    commuter_pass_fee: le16(block, 12),
                    commuter_station: self.station(block[14], block[15]),
                }
            })
            .collect()
    }

    fn sf_gate(&self, blocks: &[Block]) -> Result<SfGate> {
        require(blocks, 2, "SF改札入場情報")?;
        let (first, second) = (&blocks[0], &blocks[1]);
        let has_record = first.iter().chain(second.iter()).any(|&byte| byte != 0);

        Ok(SfGate {
            has_record,
            entry_station: self.station(first[0], first[1]),
            intermediate_entry_date: format_date(be16(second, 0)),
            intermediate_entry_time: hex::encode_upper(&second[2..4]),
            intermediate_entry_station: self.station(second[4], second[5]),
            unknown_value1_hex: format!("{:#x}", second[6]),
            intermediate_exit_time: hex::encode_upper(&second[7..9]),
            intermediate_exit_station: self.station(second[9], second[10]),
            unknown_value2_hex: format!("{:#x}", second[11]),
        })
    }

    fn paid_ticket(&self, blocks: &[Block]) -> Vec<PaidTicketEntry> {
        blocks
            .iter()
            .enumerate()
            .filter(|(_, block)| block.iter().any(|&byte| byte != 0))
            .map(|(index, block)| PaidTicketEntry {
                index,
                depart_station: self.station(block[0], block[1]),
                arrive_station: self.station(block[2], block[3]),
                expires_at: format_date(be16(block, 4)),
                issued_time: format_time(be16(block, 6)),
                issue_type_hex: hex::encode_upper(&block[8..9]),
                amount: u16::from(block[9]) * 10,
                device_id_hex: hex::encode_upper(&block[10..12]),
                checked_station: self.station(block[12], block[13]),
                checked_time: format_time(be16(block, 14)),
            })
            .collect()
    }
}

/// Attaches the per-transaction balance change to each history entry.
///
/// Entries are newest-first, so the amount moved by transaction `i` is
/// `balance[i] - balance[i + 1]`. Positive means the balance grew (a charge or
/// refund); negative means it was spent (a fare or purchase). The oldest
/// available entry has no predecessor on the card, so its delta stays `None`.
fn annotate_balance_deltas(entries: &mut [TransactionEntry]) {
    for index in 0..entries.len() {
        entries[index].delta = entries
            .get(index + 1)
            .map(|older| i64::from(entries[index].balance) - i64::from(older.balance));
    }
}

// --------------------------------------------------------------------------- //
// Orchestration                                                               //
// --------------------------------------------------------------------------- //

/// Authenticates against the server and assembles a [`CardData`].
pub struct CardDataService {
    stations: StationCodeLookup,
}

impl CardDataService {
    pub fn new(stations: StationCodeLookup) -> Self {
        Self { stations }
    }

    pub fn stations(&self) -> &StationCodeLookup {
        &self.stations
    }

    /// Reads one card end to end.
    pub fn collect(
        &self,
        client: &mut AuthClient,
        card: &mut CardSession<'_>,
        mut progress: Option<ProgressCallback<'_>>,
    ) -> Result<CardData> {
        let mut report = |value: f32| {
            if let Some(callback) = progress.as_deref_mut() {
                callback(value);
            }
        };

        // The paid-ticket service is not on every card and needs its own key.
        // Probe for it unencrypted — no server involved — and only fold it into
        // the authenticated node set when the card actually carries it.
        let (paid_present, mut paid_reason) = probe_paid_ticket(card);
        let mut services = SERVICE_NODE_IDS.to_vec();
        let mut paid_index = None;
        if paid_present {
            paid_index = Some(services.len() as u8);
            services.push(PAID_TICKET_SERVICE_NODE_ID);
        }

        let auth_result =
            match client.mutual_authentication(card, SYSTEM_CODE, &AREA_NODE_IDS, &services) {
                Ok(result) => result,
                Err(error) if paid_index.is_some() => {
                    // The extended authentication failed — most likely the server
                    // has no key for the paid-ticket node. Recover by re-polling and
                    // authenticating the known-good base set so everything else
                    // still reads; the paid-ticket service is skipped with a reason.
                    log::debug!("extended authentication failed, retrying base set: {error}");
                    paid_index = None;
                    paid_reason = Some(
                        "料金発券サービスの認証に失敗しました（サーバに鍵が無い可能性）。"
                            .to_string(),
                    );
                    card.repoll(SYSTEM_CODE).map_err(AuthError::from)?;
                    client.reset();
                    client.mutual_authentication(
                        card,
                        SYSTEM_CODE,
                        &AREA_NODE_IDS,
                        &SERVICE_NODE_IDS,
                    )?
                }
                Err(error) => return Err(error.into()),
            };
        report(30.0);

        let system = SystemInfo {
            idm_hex: hex::encode_upper(card.idm()),
            pmm_hex: hex::encode_upper(card.pmm()),
            idi_display: idi_bytes_to_str(
                &hex::decode(&auth_result.issue_id_hex)
                    .map_err(|_| CardDataError::decode("Issue ID の形式が不正です。"))?,
            ),
            idi_hex: auth_result.issue_id_hex,
            pmi: auth_result.issue_parameter_hex,
        };

        let decoder = Decoder {
            stations: &self.stations,
        };
        let mut reader = RemoteBlockReader { client, card };

        let issue_primary = decoder.issue_primary(&reader.read_blocks(0, 4)?)?;
        report(45.0);

        let attribute = decoder.attribute(&reader.read_blocks(1, 1)?)?;
        report(55.0);

        let last_topup = decoder.last_topup(&reader.read_blocks(3, 3)?)?;
        report(65.0);

        let unknown = decoder.unknown(&reader.read_blocks(2, 1)?)?;
        report(75.0);

        let transaction_history = decoder.transaction_history(&reader.read_blocks(4, 20)?);
        report(85.0);

        let commuter = decoder.commuter(&reader.read_blocks(6, 3)?)?;
        report(92.0);

        let gate = decoder.gate(&reader.read_blocks(7, 3)?);
        report(97.0);

        let sf_gate = decoder.sf_gate(&reader.read_blocks(8, 2)?)?;
        report(97.0);

        let mut paid_ticket = Vec::new();
        let mut paid_ticket_available = false;
        if let Some(service_index) = paid_index {
            match reader.read_blocks(service_index, 2) {
                Ok(blocks) => {
                    paid_ticket = decoder.paid_ticket(&blocks);
                    paid_ticket_available = true;
                    paid_reason = None;
                }
                Err(error) => {
                    paid_reason = Some(format!("料金発券情報の読み取りに失敗しました: {error}"));
                }
            }
        }
        report(100.0);

        Ok(CardData {
            system,
            issue_primary,
            attribute,
            last_topup,
            unknown,
            transaction_history,
            commuter,
            gate,
            sf_gate,
            paid_ticket,
            paid_ticket_available,
            paid_ticket_reason: paid_reason,
        })
    }
}

/// Checks, without the server, whether the card carries the paid-ticket service.
fn probe_paid_ticket(card: &mut CardSession<'_>) -> (bool, Option<String>) {
    match card.has_service(PAID_TICKET_SERVICE_NODE_ID, SYSTEM_CODE) {
        Ok(true) => (true, None),
        Ok(false) => (
            false,
            Some("カードに料金発券サービスがありません。".to_string()),
        ),
        Err(error) => (
            false,
            Some(format!("料金発券サービスの存在確認に失敗しました: {error}")),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoder(stations: &StationCodeLookup) -> Decoder<'_> {
        Decoder { stations }
    }

    fn block(bytes: &[u8]) -> Block {
        let mut block = [0u8; DATA_BLOCK_SIZE];
        block[..bytes.len()].copy_from_slice(bytes);
        block
    }

    #[test]
    fn owner_names_lose_their_padding() {
        // "山田" in Shift_JIS, space padded.
        let mut bytes = vec![0x8E, 0x52, 0x93, 0x63];
        bytes.resize(DATA_BLOCK_SIZE, b' ');
        assert_eq!(decode_owner_name(&block(&bytes)), "山田");

        let mut bytes = vec![0x8E, 0x52, 0x93, 0x63];
        bytes.resize(DATA_BLOCK_SIZE, 0x00);
        assert_eq!(decode_owner_name(&block(&bytes)), "山田");
    }

    #[test]
    fn history_stops_at_the_first_unwritten_slot() {
        let stations = StationCodeLookup::from_csv("a,b,c,d,e,f,g\n");
        let written = block(&[0x16, 0x01, 0x00, 0x02, 0x32, 0xF8, 1, 1, 1, 2, 0xE8, 0x03]);
        let blocks = vec![written, written, [0u8; DATA_BLOCK_SIZE], written];

        let entries = decoder(&stations).transaction_history(&blocks);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].recorded_by, "自動改札機");
        assert_eq!(entries[0].transaction_type, "自動改札機出場");
    }

    #[test]
    fn purchases_record_a_clock_and_no_route() {
        let stations = StationCodeLookup::from_csv("a,b,c,d,e,f,g\n");
        // transaction type 0x46 (物販) with the clock at offset 6.
        let clock = ((12u16 << 11) | (34 << 5) | 15).to_be_bytes();
        let purchase = block(&[
            0xC7, 0x46, 0x00, 0x00, 0x32, 0xF8, clock[0], clock[1], 0, 0, 0xE8, 0x03,
        ]);

        let entries = decoder(&stations).transaction_history(&[purchase]);
        assert_eq!(entries[0].transaction_time.as_deref(), Some("12:34:30"));
        assert!(entries[0].entry_station.is_none());
        assert!(entries[0].exit_station.is_none());

        // The route fields must be absent from the JSON, not null: the UI keys
        // off their absence to render a dash.
        let json = serde_json::to_value(&entries[0]).unwrap();
        assert!(json.get("entry_station").is_none());
        assert!(json.get("transaction_time").is_some());
    }

    #[test]
    fn balance_deltas_run_newest_to_oldest() {
        let stations = StationCodeLookup::from_csv("a,b,c,d,e,f,g\n");
        let with_balance = |balance: u16| {
            let bytes = balance.to_le_bytes();
            block(&[
                0x16, 0x01, 0x00, 0x02, 0x32, 0xF8, 1, 1, 1, 2, bytes[0], bytes[1],
            ])
        };

        let entries = decoder(&stations).transaction_history(&[
            with_balance(1000),
            with_balance(1200),
            with_balance(700),
        ]);
        assert_eq!(entries[0].delta, Some(-200));
        assert_eq!(entries[1].delta, Some(500));
        // The oldest entry has nothing to compare against.
        assert_eq!(entries[2].delta, None);
    }

    #[test]
    fn zero_filled_gate_and_paid_slots_are_dropped() {
        let stations = StationCodeLookup::from_csv("a,b,c,d,e,f,g\n");
        let used = block(&[0xA0, 0x00, 1, 1, 0xAB, 0xCD, 0x32, 0xF8, 0x12, 0x34]);
        let empty = [0u8; DATA_BLOCK_SIZE];

        let gates = decoder(&stations).gate(&[used, empty, used]);
        assert_eq!(gates.len(), 2);
        // The index stays the card's slot number, not the row number.
        assert_eq!(gates[1].index, 2);
        assert_eq!(gates[0].time, "12:34");
        assert_eq!(gates[0].device_id_hex, "ABCD");
        assert_eq!(gates[0].gate_in_out_type, "入場");

        assert!(decoder(&stations).paid_ticket(&[empty, empty]).is_empty());
    }

    #[test]
    fn paid_ticket_fees_are_stored_divided_by_ten() {
        let stations = StationCodeLookup::from_csv("a,b,c,d,e,f,g\n");
        let entry = block(&[1, 1, 2, 2, 0x32, 0xF8, 0, 0, 0x01, 82, 0xAB, 0xCD]);
        let tickets = decoder(&stations).paid_ticket(&[entry]);
        assert_eq!(tickets[0].amount, 820);
        assert_eq!(tickets[0].issue_type_hex, "01");
    }

    #[test]
    fn an_all_zero_sf_gate_block_pair_reports_no_record() {
        let stations = StationCodeLookup::from_csv("a,b,c,d,e,f,g\n");
        let empty = [0u8; DATA_BLOCK_SIZE];
        assert!(
            !decoder(&stations)
                .sf_gate(&[empty, empty])
                .unwrap()
                .has_record
        );

        let used = block(&[1, 1]);
        assert!(
            decoder(&stations)
                .sf_gate(&[used, empty])
                .unwrap()
                .has_record
        );
    }

    #[test]
    fn short_reads_are_reported_rather_than_panicking() {
        let stations = StationCodeLookup::from_csv("a,b,c,d,e,f,g\n");
        let one = vec![[0u8; DATA_BLOCK_SIZE]];
        assert!(decoder(&stations).issue_primary(&one).is_err());
        assert!(decoder(&stations).commuter(&one).is_err());
        assert!(decoder(&stations).sf_gate(&one).is_err());
        assert!(decoder(&stations).attribute(&[]).is_err());
    }

    #[test]
    fn commuter_presence_keys_off_the_start_date() {
        let stations = StationCodeLookup::from_csv("a,b,c,d,e,f,g\n");
        let blocks = vec![[0u8; DATA_BLOCK_SIZE]; 3];
        let commuter = decoder(&stations).commuter(&blocks).unwrap();
        assert_eq!(commuter.valid_from, "—");
    }
}
