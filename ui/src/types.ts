export interface SystemInfo {
  idm_hex: string;
  pmm_hex: string;
  idi_hex: string;
  idi_display: string;
  pmi: string;
}

export interface IssuePrimary {
  owner_name: string;
  secondary_issue_id: string;
  owner_phone_hex: string;
  owner_age_code: string;
  owner_birthdate: string;
  deposit: number;
  issuer_id: string;
  issuer_id_hex: string;
  issued_by_code: number;
  issued_by: string;
  issued_station: string;
  issued_at: string;
  expires_at: string;
  collected: boolean;
}

export interface Attribute {
  balance: number;
  transaction_number: number;
  voice_guidance: boolean;
  sf_outside_commuter: boolean;
  touch_de_go: boolean;
}

export interface LastTopup {
  equipment_code: number;
  equipment: string;
  station: string;
  amount: number;
}

export interface UnknownInfo {
  balance: number;
  date: string;
  transaction_number: number;
}

export interface TransactionEntry {
  index: number;
  recorded_on: string;
  recorded_by_code: number;
  recorded_by: string;
  transaction_type_code: number;
  transaction_type: string;
  pay_type_code: number;
  pay_type: string;
  gate_instruction_type_code: number;
  gate_instruction_type: string;
  transaction_time?: string;
  entry_station?: string;
  exit_station?: string;
  balance: number;
  transaction_number: number;
  delta: number | null;
}

export interface Commuter {
  issuer_id: string;
  issuer_id_hex: string;
  valid_from: string;
  valid_to: string;
  start_station: string;
  end_station: string;
  via1_station: string;
  via2_station: string;
  issued_at: string;
  pass_number: string;
  r_number: string;
  sale_price: number;
  purchase_pay_type_code: number;
  purchase_pay_type: string;
  commuter_certificate_expiry: string;
}

export interface AutoCharge {
  contracted: boolean;
  enabled: boolean;
  charge_amount: number;
  threshold: number;
}

export interface GateEntry {
  index: number;
  date: string;
  time: string;
  gate_in_out_type_code: number;
  gate_in_out_type: string;
  intermediate_gate_instruction_type_code: number;
  intermediate_gate_instruction_type: string;
  station: string;
  device_id_hex: string;
  amount: number;
  commuter_pass_fee: number;
  commuter_station: string;
}

export interface SfGate {
  has_record: boolean;
  entry_station: string;
  intermediate_entry_date: string;
  intermediate_entry_time: string;
  intermediate_entry_station: string;
  unknown_value1_hex: string;
  intermediate_exit_time: string;
  intermediate_exit_station: string;
  unknown_value2_hex: string;
}

export interface PaidTicketEntry {
  index: number;
  depart_station: string;
  arrive_station: string;
  expires_at: string;
  issued_time: string;
  issue_type_hex: string;
  amount: number;
  device_id_hex: string;
  checked_station: string;
  checked_time: string;
}

export interface CardData {
  system: SystemInfo;
  issue_primary: IssuePrimary;
  attribute: Attribute;
  last_topup: LastTopup;
  unknown: UnknownInfo;
  transaction_history: TransactionEntry[];
  commuter: Commuter;
  auto_charge: AutoCharge;
  gate: GateEntry[];
  sf_gate: SfGate;
  paid_ticket: PaidTicketEntry[];
  paid_ticket_available: boolean;
  paid_ticket_reason: string | null;
}

export type ReaderState = "initializing" | "waiting" | "reading" | "done" | "error";

export type ReaderEvent =
  | { type: "status"; state: ReaderState; message: string }
  | { type: "progress"; value: number }
  | { type: "card"; read_at: string; data: CardData }
  | { type: "error"; message: string }
  | { type: "removed" };
