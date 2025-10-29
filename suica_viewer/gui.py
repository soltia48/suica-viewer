import json
import os
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Literal

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import nfc
from nfc.tag import Tag
from nfc.tag.tt3_sony import FelicaStandard

from .auth_client import FelicaRemoteClient, FelicaRemoteClientError
from .station_code_lookup import StationCodeLookup
from .utils import (
    SYSTEM_CODE,
    CARD_TYPE_LABELS,
    equipment_type_to_str,
    format_date,
    format_station,
    format_time,
    gate_in_out_type_to_str,
    gate_instruction_type_to_str,
    idi_bytes_to_str,
    intermadiate_gate_instruction_type_to_str,
    pay_type_to_str,
    transaction_type_to_str,
)


AREA_NODE_IDS: tuple[int, ...] = (0x0000, 0x0040, 0x0800, 0x0FC0, 0x1000)
SERVICE_NODE_IDS: tuple[int, ...] = (
    0x0048,
    0x0088,
    0x0810,
    0x08C8,
    0x090C,
    0x1008,
    0x1048,
    0x108C,
    0x10C8,
)

READ_COMMAND_CODE = 0x14
DATA_BLOCK_SIZE = 16
MAX_BLOCKS_PER_REQUEST = 12
DEFAULT_AUTH_SERVER_URL = "https://felica-auth.nyaa.ws"

SUMMARY_VAR_KEYS: tuple[str, ...] = (
    "idi",
    "pmi",
    "owner_name",
    "card_type",
    "balance",
    "region",
    "deposit",
    "initial_amount",
    "issued_at",
    "expires_at",
    "issued_station",
    "transaction_number",
    "commuter_pass",
)
COMMUTER_DETAIL_KEYS: tuple[str, ...] = (
    "valid_from",
    "valid_to",
    "start_station",
    "end_station",
    "via1",
    "via2",
    "issued_at",
)
SF_GATE_VAR_KEYS: tuple[str, ...] = (
    "entry_station",
    "intermediate_entry",
    "intermediate_entry_date",
    "intermediate_entry_time",
    "intermediate_exit",
    "intermediate_exit_time",
    "unknown_value1",
    "unknown_value2",
)
ISSUE_DETAIL_SECTIONS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    (
        "発行情報1",
        (
            ("所有者名", "owner_name"),
            ("所有者電話番号", "owner_phone_hex"),
            ("所有者年齢", "owner_age_code"),
            ("所有者生年月日", "owner_birthdate"),
            ("第二発行ID", "secondary_issue_id"),
            ("発行者ID", "issuer_id"),
            ("デポジット額", "deposit"),
            ("発行機器", "issued_by"),
            ("発行駅", "issued_station"),
            ("発行日", "issued_at"),
            ("有効期限", "expires_at"),
        ),
    ),
    (
        "発行情報2",
        (
            ("発行機器", "issued_by_detail"),
            ("発行駅", "issued_station_detail"),
            ("初期残高", "initial_amount"),
        ),
    ),
    (
        "属性情報",
        (
            ("カード種別", "card_type"),
            ("地域", "region_display"),
            ("残高", "attribute_balance"),
            ("取引通番", "attribute_transaction_number"),
        ),
    ),
)
MISC_DETAIL_FIELDS: tuple[tuple[str, str], ...] = (
    ("不明な残高", "unknown_balance"),
    ("不明な日付", "unknown_date"),
    ("不明な取引通番", "unknown_transaction_number"),
)
HISTORY_FILTER_FIELDS: tuple[str, ...] = (
    "recorded_on",
    "transaction_type",
    "pay_type",
    "gate_instruction_type",
    "entry_station",
    "exit_station",
    "recorded_by",
)


class RemoteCardReader:
    """Proxy that issues encrypted read commands through the remote server."""

    def __init__(self, client: FelicaRemoteClient) -> None:
        self.client = client

    def read_blocks(self, service_index: int, indexes: Iterable[int]) -> list[bytes]:
        index_list = list(indexes)
        blocks: list[bytes] = []
        for chunk_start in range(0, len(index_list), MAX_BLOCKS_PER_REQUEST):
            chunk = index_list[chunk_start : chunk_start + MAX_BLOCKS_PER_REQUEST]
            if not chunk:
                continue
            elements = [(service_index, block_index) for block_index in chunk]
            blocks.extend(self._read_elements(elements))
        return blocks

    def _read_elements(self, elements: list[tuple[int, int]]) -> list[bytes]:
        payload = bytes([len(elements)]) + self._elements_to_bytes(elements)
        response = self.client.encryption_exchange(READ_COMMAND_CODE, payload)
        if len(response) < 3:
            raise RuntimeError("リモートサーバーからの応答が不正です。")

        status_flag1, status_flag2 = response[0], response[1]
        if status_flag1 != 0x00:
            status_code = (status_flag1 << 8) | status_flag2
            raise RuntimeError(f"カードがエラーを返しました: 0x{status_code:04X}")

        expected_blocks = len(elements)
        block_count = response[2]
        if block_count != expected_blocks:
            raise RuntimeError("取得したブロック数が一致しません。")

        block_payload = response[3:]
        expected_length = expected_blocks * DATA_BLOCK_SIZE
        if len(block_payload) < expected_length:
            raise RuntimeError("ブロックデータの長さが不正です。")
        block_payload = block_payload[:expected_length]

        return [
            block_payload[i * DATA_BLOCK_SIZE : (i + 1) * DATA_BLOCK_SIZE]
            for i in range(expected_blocks)
        ]

    @staticmethod
    def _elements_to_bytes(elements: list[tuple[int, int]]) -> bytes:
        encoded = bytearray()
        for service_index, block_number in elements:
            if not 0 <= service_index < 16:
                raise ValueError(
                    "サービスインデックスは 0 から 15 の範囲である必要があります。"
                )
            if not 0 <= block_number < 256:
                raise ValueError(
                    "ブロック番号は 0 から 255 の範囲である必要があります。"
                )
            encoded.append(0x80 | service_index)
            encoded.append(block_number & 0xFF)
        return bytes(encoded)


@dataclass
class SystemInfo:
    idi_hex: str
    idi_display: str
    pmi: str


@dataclass(frozen=True)
class TreeColumnSpec:
    heading: str
    width: int
    anchor: str | None = None


ProgressCallback = Callable[[float], None]


@dataclass
class CardData:
    system: SystemInfo
    issue_primary: dict[str, Any]
    attribute: dict[str, Any]
    issue_secondary: dict[str, Any]
    unknown: dict[str, Any]
    transaction_history: list[dict[str, Any]]
    commuter: dict[str, Any]
    gate: list[dict[str, Any]]
    sf_gate: dict[str, Any]

    def to_serializable_dict(self) -> dict[str, Any]:
        return {
            "system": {
                "idi_hex": self.system.idi_hex,
                "idi_display": self.system.idi_display,
                "pmi": self.system.pmi,
            },
            "issue_primary": dict(self.issue_primary),
            "attribute": dict(self.attribute),
            "issue_secondary": dict(self.issue_secondary),
            "unknown": dict(self.unknown),
            "transaction_history": [dict(entry) for entry in self.transaction_history],
            "commuter": dict(self.commuter),
            "gate": [dict(entry) for entry in self.gate],
            "sf_gate": dict(self.sf_gate),
        }


class SuicaCardDataExtractor:
    """Extracts structured data from a Suica Felica tag."""

    def __init__(
        self,
        reader: RemoteCardReader,
        station_code_lookup: StationCodeLookup,
    ):
        self.reader = reader
        self.station_code_lookup = station_code_lookup

    def _format_station(self, line_code: int, station_order: int) -> str:
        return format_station(self.station_code_lookup, line_code, station_order)

    def _read_blocks(self, service_index: int, indexes: Iterable[int]) -> list[bytes]:
        return self.reader.read_blocks(service_index, indexes)

    def _read_single_block(self, service_code: int, index: int) -> bytes:
        return self._read_blocks(service_code, [index])[0]

    def read_issue_information_primary(self) -> dict[str, Any]:
        owner_block, personal_block, secondary_idi_block, metadata_block = (
            self._read_blocks(0, range(4))
        )

        try:
            owner_name = owner_block.decode("shift_jis").rstrip()
        except UnicodeDecodeError:
            owner_name = owner_block.decode("shift_jis", errors="ignore").rstrip()

        phone_number = personal_block[0:8].hex().upper().rstrip("F")
        age_code = personal_block[8:9].hex().upper()
        dob = int.from_bytes(personal_block[9:11], byteorder="big")
        deposit = int.from_bytes(personal_block[12:14], byteorder="little")
        issuer_id = metadata_block[0:2].hex().upper()
        issued_by_code = metadata_block[2]
        issued_by = equipment_type_to_str(issued_by_code)
        issued_station_line = metadata_block[3]
        issued_station_order = metadata_block[4]
        issued_station = self._format_station(issued_station_line, issued_station_order)
        issued_at = int.from_bytes(metadata_block[7:9], byteorder="big")
        expires_at = int.from_bytes(metadata_block[14:16], byteorder="big")

        return {
            "owner_name": owner_name,
            "secondary_issue_id": idi_bytes_to_str(secondary_idi_block),
            "owner_phone_hex": phone_number,
            "owner_age_code": age_code,
            "owner_birthdate": format_date(dob),
            "deposit": deposit,
            "issuer_id": issuer_id,
            "issued_by_code": issued_by_code,
            "issued_by": issued_by,
            "issued_station": issued_station,
            "issued_at": format_date(issued_at),
            "expires_at": format_date(expires_at),
        }

    def read_attribute_information(self) -> dict[str, Any]:
        block = self._read_single_block(1, 0)

        card_type_code = block[8] >> 4
        card_type_label = CARD_TYPE_LABELS.get(card_type_code, "不明")
        region_code = block[8] & 0x0F
        amount = int.from_bytes(block[11:13], byteorder="little")
        transaction_number = int.from_bytes(block[14:16], byteorder="big")

        return {
            "card_type_code": card_type_code,
            "card_type": card_type_label,
            "region": region_code,
            "balance": amount,
            "transaction_number": transaction_number,
        }

    def read_unknown_information(self) -> dict[str, Any]:
        block = self._read_single_block(2, 0)

        amount = int.from_bytes(block[0:2], byteorder="little")
        issued_at = int.from_bytes(block[8:10], byteorder="big")
        transaction_number = int.from_bytes(block[14:16], byteorder="big")

        return {
            "balance": amount,
            "date": format_date(issued_at),
            "transaction_number": transaction_number,
        }

    def read_issue_information_secondary(self) -> dict[str, Any]:
        detail_block, *_ = self._read_blocks(3, range(3))

        issued_by_code = detail_block[0]
        issued_station_line = detail_block[1]
        issued_station_order = detail_block[2]
        issued_station = self._format_station(issued_station_line, issued_station_order)
        initial_amount = int.from_bytes(detail_block[5:7], byteorder="little")

        return {
            "issued_by_code": issued_by_code,
            "issued_by": equipment_type_to_str(issued_by_code),
            "issued_station": issued_station,
            "initial_amount": initial_amount,
        }

    def read_transaction_history(self) -> list[dict[str, Any]]:
        blocks = self._read_blocks(4, range(20))
        entries: list[dict[str, Any]] = []

        for index, block in enumerate(blocks):
            recorded_by = block[0]
            if recorded_by == 0x00:
                break

            transaction_type_code = block[1] & 0x7F
            pay_type_code = block[2]
            gate_instruction_type_code = block[3]
            recorded_at = int.from_bytes(block[4:6], byteorder="big")

            entry: dict[str, Any] = {
                "index": index,
                "recorded_on": format_date(recorded_at),
                "recorded_by_code": recorded_by,
                "recorded_by": equipment_type_to_str(recorded_by),
                "transaction_type_code": transaction_type_code,
                "transaction_type": transaction_type_to_str(transaction_type_code),
                "pay_type_code": pay_type_code,
                "pay_type": pay_type_to_str(pay_type_code),
                "gate_instruction_type_code": gate_instruction_type_code,
                "gate_instruction_type": gate_instruction_type_to_str(
                    gate_instruction_type_code
                ),
            }

            if transaction_type_code == 0x46:
                time_value = int.from_bytes(block[6:8], byteorder="big")
                entry["transaction_time"] = format_time(time_value)
            else:
                entry_station_line = block[6]
                entry_station_order = block[7]
                exit_station_line = block[8]
                exit_station_order = block[9]
                entry["entry_station"] = self._format_station(
                    entry_station_line, entry_station_order
                )
                entry["exit_station"] = self._format_station(
                    exit_station_line, exit_station_order
                )

            amount = int.from_bytes(block[10:12], byteorder="little")
            transaction_number = int.from_bytes(block[13:15], byteorder="big")
            entry["balance"] = amount
            entry["transaction_number"] = transaction_number

            entries.append(entry)

        return entries

    def read_commuter_pass_information(self) -> dict[str, Any]:
        primary_block, _, supplemental_block = self._read_blocks(6, range(3))

        start_at = int.from_bytes(primary_block[0:2], byteorder="big")
        end_at = int.from_bytes(primary_block[2:4], byteorder="big")
        via1_station = self._format_station(primary_block[12], primary_block[13])
        via2_station = self._format_station(primary_block[14], primary_block[15])

        return {
            "valid_from": format_date(start_at),
            "valid_to": format_date(end_at),
            "start_station": self._format_station(primary_block[8], primary_block[9]),
            "end_station": self._format_station(primary_block[10], primary_block[11]),
            "via1_station": via1_station,
            "via2_station": via2_station,
            "issued_at": format_date(
                int.from_bytes(supplemental_block[5:7], byteorder="big")
            ),
        }

    def read_gate_in_out_information(self) -> list[dict[str, Any]]:
        blocks = self._read_blocks(7, range(3))
        entries: list[dict[str, Any]] = []

        for index, block in enumerate(blocks):
            date = int.from_bytes(block[6:8], byteorder="big")
            time_hex = block[8:10].hex().upper()
            entries.append(
                {
                    "index": index,
                    "date": format_date(date),
                    "time": f"{time_hex[0:2]}:{time_hex[2:4]}",
                    "gate_in_out_type_code": block[0],
                    "gate_in_out_type": gate_in_out_type_to_str(block[0]),
                    "intermediate_gate_instruction_type_code": block[1],
                    "intermediate_gate_instruction_type": (
                        intermadiate_gate_instruction_type_to_str(block[1])
                    ),
                    "station": self._format_station(block[2], block[3]),
                    "device_id_hex": block[4:6].hex().upper(),
                    "amount": int.from_bytes(block[10:12], byteorder="little"),
                    "commuter_pass_fee": int.from_bytes(
                        block[12:14], byteorder="little"
                    ),
                    "commuter_station": self._format_station(block[14], block[15]),
                }
            )

        return entries

    def read_sf_gate_in_information(self) -> dict[str, Any]:
        first_block, second_block = self._read_blocks(8, range(2))

        entry_station_line = first_block[0]
        entry_station_order = first_block[1]
        intermadiate_entry_station_line = second_block[4]
        intermadiate_entry_station_order = second_block[5]
        intermadiate_exit_station_line = second_block[9]
        intermadiate_exit_station_order = second_block[10]

        return {
            "entry_station": self._format_station(
                entry_station_line, entry_station_order
            ),
            "intermediate_entry_date": format_date(
                int.from_bytes(second_block[0:2], byteorder="big")
            ),
            "intermediate_entry_time": second_block[2:4].hex().upper(),
            "intermediate_entry_station": self._format_station(
                intermadiate_entry_station_line, intermadiate_entry_station_order
            ),
            "unknown_value1_hex": hex(second_block[6]),
            "intermediate_exit_time": second_block[7:9].hex().upper(),
            "intermediate_exit_station": self._format_station(
                intermadiate_exit_station_line, intermadiate_exit_station_order
            ),
            "unknown_value2_hex": hex(second_block[11]),
        }


class CardDataService:
    """Coordinates remote reads and assembles card data."""

    def __init__(self, station_code_lookup: StationCodeLookup) -> None:
        self.station_code_lookup = station_code_lookup

    def collect(
        self,
        client: FelicaRemoteClient,
        *,
        progress_callback: ProgressCallback | None = None,
    ) -> CardData:
        auth_result = client.mutual_authentication(
            SYSTEM_CODE,
            list(AREA_NODE_IDS),
            list(SERVICE_NODE_IDS),
        )
        self._update_progress(progress_callback, 30.0)

        system_info = self._build_system_info(auth_result)

        reader = RemoteCardReader(client)
        extractor = SuicaCardDataExtractor(reader, self.station_code_lookup)

        issue_primary = extractor.read_issue_information_primary()
        self._update_progress(progress_callback, 45.0)

        attribute_info = extractor.read_attribute_information()
        self._update_progress(progress_callback, 55.0)

        issue_secondary = extractor.read_issue_information_secondary()
        self._update_progress(progress_callback, 65.0)

        unknown_info = extractor.read_unknown_information()
        self._update_progress(progress_callback, 75.0)

        transaction_history = extractor.read_transaction_history()
        self._update_progress(progress_callback, 85.0)

        commuter_info = extractor.read_commuter_pass_information()
        self._update_progress(progress_callback, 92.0)

        gate_info = extractor.read_gate_in_out_information()
        self._update_progress(progress_callback, 97.0)

        sf_gate_info = extractor.read_sf_gate_in_information()
        self._update_progress(progress_callback, 100.0)

        return CardData(
            system=system_info,
            issue_primary=issue_primary,
            attribute=attribute_info,
            issue_secondary=issue_secondary,
            unknown=unknown_info,
            transaction_history=transaction_history,
            commuter=commuter_info,
            gate=gate_info,
            sf_gate=sf_gate_info,
        )

    def _build_system_info(self, auth_result: dict[str, Any]) -> SystemInfo:
        idi_hex = (auth_result.get("issue_id") or auth_result.get("idi") or "").upper()
        pmi_hex = (
            auth_result.get("issue_parameter") or auth_result.get("pmi") or ""
        ).upper()

        if not idi_hex:
            raise RuntimeError("サーバ応答に Issue ID が含まれていません。")
        if not pmi_hex:
            raise RuntimeError("サーバ応答に Issue Parameter が含まれていません。")

        try:
            idi_bytes = bytes.fromhex(idi_hex)
        except ValueError as exc:
            raise RuntimeError("Issue ID の形式が不正です。") from exc

        return SystemInfo(
            idi_hex=idi_hex,
            idi_display=idi_bytes_to_str(idi_bytes),
            pmi=pmi_hex,
        )

    @staticmethod
    def _update_progress(
        callback: ProgressCallback | None,
        value: float,
    ) -> None:
        if callback is not None:
            callback(value)


class SuicaGuiApp:
    """Tkinter-based GUI that shows Suica IC card information."""

    def __init__(self) -> None:
        self.root = self._create_root_window()
        self._configure_style()
        self._initialize_state()
        self._load_station_data()
        self.scrollable_container = self._create_scrollable_container()
        self._build_ui()
        self._register_event_handlers()
        self._start_nfc_thread()

    def _create_root_window(self) -> tk.Tk:
        root = tk.Tk()
        root.title("Suica ビューア")
        root.geometry("1440x900")
        root.minsize(1024, 768)
        return root

    def _initialize_state(self) -> None:
        self.status_var = tk.StringVar(
            master=self.root, value="カードをかざしてください。"
        )
        self.last_updated_var = tk.StringVar(master=self.root, value="最終更新: —")
        self.progress_var = tk.DoubleVar(master=self.root, value=0.0)
        self.summary_vars = self._create_string_vars(SUMMARY_VAR_KEYS)
        self.history_filter_var = tk.StringVar(master=self.root)
        self.current_history: list[dict[str, Any]] = []
        self.current_card_json = ""
        self.copy_details_button: ttk.Button | None = None
        self.export_details_button: ttk.Button | None = None
        self.history_filter_entry: ttk.Entry | None = None
        self.history_tree: ttk.Treeview | None = None
        self.gate_tree: ttk.Treeview | None = None
        self.current_gate_entries: list[dict[str, Any]] = []
        self.sf_gate_vars = self._create_string_vars(SF_GATE_VAR_KEYS)
        self.commuter_detail_vars = self._create_string_vars(COMMUTER_DETAIL_KEYS)
        self.issue_detail_sections = ISSUE_DETAIL_SECTIONS
        issue_keys = [
            key for _, fields in self.issue_detail_sections for _, key in fields
        ]
        self.issue_detail_vars = self._create_string_vars(issue_keys)
        self.misc_detail_fields = MISC_DETAIL_FIELDS
        misc_keys = [key for _, key in self.misc_detail_fields]
        self.misc_detail_vars = self._create_string_vars(misc_keys)
        self.server_url = self._resolve_server_url()
        self._remote_client: FelicaRemoteClient | None = None
        self.card_data_service: CardDataService | None = None
        self.progress_bar: ttk.Progressbar | None = None
        self.details_text: tk.Text | None = None

    def _create_string_vars(
        self,
        keys: Iterable[str],
        *,
        default: str = "-",
    ) -> dict[str, tk.StringVar]:
        return {key: tk.StringVar(master=self.root, value=default) for key in keys}

    def _load_station_data(self) -> None:
        try:
            self.station_code_lookup = StationCodeLookup()
            self.card_data_service = CardDataService(self.station_code_lookup)
        except Exception as exc:
            messagebox.showerror(
                "駅データ読み込みエラー",
                f"station_codes.csv を読み込めませんでした: {exc}",
            )
            self.root.destroy()
            raise SystemExit(1) from exc

    def _register_event_handlers(self) -> None:
        self.root.bind("<Control-f>", self._focus_history_filter)
        self.root.bind("<Command-f>", self._focus_history_filter)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _resolve_server_url(self) -> str:
        value = os.environ.get("AUTH_SERVER_URL", "").strip()
        return value or DEFAULT_AUTH_SERVER_URL

    def _get_remote_client(self, tag: FelicaStandard) -> FelicaRemoteClient:
        if self._remote_client is None:
            self._remote_client = FelicaRemoteClient(self.server_url, tag)
        else:
            self._remote_client.reset(tag)
        return self._remote_client

    def _start_nfc_thread(self) -> None:
        self.nfc_thread = threading.Thread(target=self._nfc_loop, daemon=True)
        self.nfc_thread.start()

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            # Fallback to the default theme if "clam" is unavailable.
            pass
        self.root.configure(bg="#f3f4f8")

        base_font = ("Helvetica", 12)
        self.root.option_add("*TLabel.font", base_font)
        self.root.option_add("*TButton.font", base_font)
        self.root.option_add("*Treeview.font", base_font)
        self.root.option_add("*TEntry.font", base_font)

        style.configure("Main.TFrame", background="#f3f4f8")
        style.configure("SectionWrapper.TFrame", background="#f3f4f8")
        style.configure(
            "SectionBody.TFrame",
            background="#ffffff",
            borderwidth=1,
            relief="solid",
        )
        style.configure("SectionInner.TFrame", background="#ffffff")

        style.configure(
            "Treeview",
            rowheight=28,
            background="#ffffff",
            fieldbackground="#ffffff",
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            font=("Helvetica", 13, "bold"),
            background="#eef1f7",
            foreground="#1f2937",
            borderwidth=0,
        )
        style.configure(
            "Status.TLabel",
            font=("Helvetica", 16, "bold"),
            background="#f3f4f8",
            foreground="#1f2937",
        )
        style.configure(
            "SummaryKey.TLabel",
            font=("Helvetica", 12, "bold"),
            background="#ffffff",
            foreground="#374151",
        )
        style.configure(
            "SummaryValue.TLabel",
            font=("Helvetica", 12),
            background="#ffffff",
            foreground="#111827",
        )
        style.configure(
            "Meta.TLabel",
            font=("Helvetica", 11),
            foreground="#666666",
            background="#f3f4f8",
        )
        style.configure(
            "SectionMeta.TLabel",
            font=("Helvetica", 11),
            foreground="#6b7280",
            background="#ffffff",
        )
        style.configure(
            "SectionHeader.TLabel",
            font=("Helvetica", 13, "bold"),
            background="#f3f4f8",
            foreground="#1f2937",
        )
        style.configure(
            "SubsectionHeader.TLabel",
            font=("Helvetica", 12, "bold"),
            background="#ffffff",
            foreground="#1f2937",
        )
        style.configure("TNotebook", background="#f3f4f8", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(12, 6), font=("Helvetica", 12))
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#ffffff"), ("!selected", "#f3f4f8")],
            foreground=[("selected", "#111827"), ("!selected", "#4b5563")],
        )
        style.configure(
            "Status.Horizontal.TProgressbar",
            troughcolor="#dbe1ef",
            background="#4c6ef5",
            bordercolor="#dbe1ef",
        )
        style.map(
            "Treeview",
            background=[("selected", "#e0ecff")],
            foreground=[("selected", "#000000")],
        )

    def _create_scrollable_container(self) -> ttk.Frame:
        container = ttk.Frame(self.root, style="Main.TFrame")
        container.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(
            container,
            highlightthickness=0,
            background="#f3f4f8",
            borderwidth=0,
        )
        scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        content_frame = ttk.Frame(canvas, style="Main.TFrame")
        window_id = canvas.create_window((0, 0), window=content_frame, anchor="nw")

        content_frame.bind(
            "<Configure>",
            lambda event: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.bind(
            "<Configure>",
            lambda event: canvas.itemconfigure(window_id, width=event.width),
        )

        def _on_mousewheel(event: Any) -> None:
            delta = 0
            if hasattr(event, "delta") and event.delta:
                delta = event.delta
            elif getattr(event, "num", None) == 4:
                delta = 120
            elif getattr(event, "num", None) == 5:
                delta = -120

            if delta > 0:
                canvas.yview_scroll(-1, "units")
            elif delta < 0:
                canvas.yview_scroll(1, "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        canvas.bind_all("<Button-4>", _on_mousewheel)
        canvas.bind_all("<Button-5>", _on_mousewheel)

        self._scroll_canvas = canvas
        return content_frame

    def _build_ui(self) -> None:
        main_frame = ttk.Frame(
            self.scrollable_container, padding=24, style="Main.TFrame"
        )
        main_frame.pack(fill=tk.BOTH, expand=True)

        header_frame = ttk.Frame(main_frame, padding=(0, 0, 0, 16), style="Main.TFrame")
        header_frame.pack(fill=tk.X)
        header_frame.columnconfigure(0, weight=1)
        header_frame.columnconfigure(1, weight=0)

        status_label = ttk.Label(
            header_frame,
            textvariable=self.status_var,
            style="Status.TLabel",
            anchor="w",
        )
        status_label.grid(row=0, column=0, sticky="w")

        self.progress_bar = ttk.Progressbar(
            header_frame,
            variable=self.progress_var,
            maximum=100,
            mode="determinate",
            style="Status.Horizontal.TProgressbar",
        )
        self.progress_bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(12, 0))

        ttk.Label(
            header_frame,
            textvariable=self.last_updated_var,
            style="Meta.TLabel",
            anchor="e",
        ).grid(row=0, column=1, sticky="e", padx=(16, 0))

        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 16))

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        overview_frame = ttk.Frame(notebook, padding=16, style="Main.TFrame")
        notebook.add(overview_frame, text="概要")

        issue_frame = ttk.Frame(notebook, padding=16, style="Main.TFrame")
        notebook.add(issue_frame, text="発行情報")

        history_frame = ttk.Frame(notebook, padding=16, style="Main.TFrame")
        notebook.add(history_frame, text="履歴")

        gate_frame = ttk.Frame(notebook, padding=16, style="Main.TFrame")
        notebook.add(gate_frame, text="改札")

        misc_frame = ttk.Frame(notebook, padding=16, style="Main.TFrame")
        notebook.add(misc_frame, text="その他")

        details_frame = ttk.Frame(notebook, padding=16, style="Main.TFrame")
        notebook.add(details_frame, text="詳細")

        self._build_overview_tab(overview_frame)
        self._build_issue_tab(issue_frame)
        self._build_history_tab(history_frame)
        self._build_gate_tab(gate_frame)
        self._build_misc_tab(misc_frame)
        self._build_details_tab(details_frame)

    def _populate_label_value_grid(
        self,
        frame: tk.Widget,
        items: Iterable[tuple[str, str]],
        variables: dict[str, tk.StringVar],
        *,
        label_width: int,
        wraplength: int = 900,
        padx: tuple[int, int] = (0, 12),
        pady: int = 4,
        label_style: str = "SummaryKey.TLabel",
        value_style: str = "SummaryValue.TLabel",
    ) -> None:
        for row, (label_text, key) in enumerate(items):
            ttk.Label(
                frame,
                text=f"{label_text}:",
                width=label_width,
                anchor="e",
                style=label_style,
            ).grid(row=row, column=0, sticky="e", pady=pady, padx=padx)
            ttk.Label(
                frame,
                textvariable=variables[key],
                style=value_style,
                anchor="w",
                wraplength=wraplength,
            ).grid(row=row, column=1, sticky="w", pady=pady)

    def _create_section(
        self,
        parent: tk.Widget,
        title: str,
        *,
        padding: int | tuple[int, int, int, int] = 12,
        margin: tuple[int, int] = (0, 16),
        fill: Literal["none", "x", "y", "both"] = "x",
        expand: bool = False,
        variant: Literal["primary", "embedded"] = "primary",
    ) -> ttk.Frame:
        if variant == "embedded":
            wrapper_style = "SectionInner.TFrame"
            header_style = "SubsectionHeader.TLabel"
            pack_kwargs: dict[str, Any] = {"pady": margin}
        else:
            wrapper_style = "SectionWrapper.TFrame"
            header_style = "SectionHeader.TLabel"
            pack_kwargs = {"pady": margin, "padx": 4}

        section_wrapper = ttk.Frame(parent, style=wrapper_style)
        section_wrapper.pack(fill=fill, expand=expand, **pack_kwargs)

        header_row = ttk.Frame(section_wrapper, style=wrapper_style)
        header_row.pack(fill=tk.X)
        ttk.Label(header_row, text=title, style=header_style).pack(side=tk.LEFT)

        if isinstance(padding, tuple):
            padding_values = padding
        else:
            padding_values = (padding, padding, padding, padding)

        content = ttk.Frame(
            section_wrapper,
            padding=padding_values,
            style="SectionBody.TFrame",
        )
        content.pack(fill=fill, expand=expand, pady=(6, 0))
        return content

    def _create_treeview(
        self,
        parent: ttk.Frame,
        column_specs: Iterable[TreeColumnSpec],
        *,
        odd_row_color: str,
        even_row_color: str = "#fafafa",
    ) -> ttk.Treeview:
        specs = list(column_specs)
        column_ids = [spec.heading for spec in specs]
        tree = ttk.Treeview(
            parent, columns=column_ids, show="headings", selectmode="browse"
        )
        for spec in specs:
            tree.heading(spec.heading, text=spec.heading)
            column_kwargs: dict[str, Any] = {"width": spec.width}
            if spec.anchor:
                column_kwargs["anchor"] = spec.anchor
            tree.column(spec.heading, **column_kwargs)

        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT)

        tree.tag_configure("even", background=even_row_color)
        tree.tag_configure("odd", background=odd_row_color)
        return tree

    def _build_overview_tab(self, frame: ttk.Frame) -> None:
        sections = [
            (
                "残高情報",
                [
                    ("残高", "balance"),
                    ("デポジット", "deposit"),
                    ("初期残高", "initial_amount"),
                ],
            ),
            (
                "カード識別",
                [
                    ("IDi", "idi"),
                    ("PMi", "pmi"),
                    ("カード種別", "card_type"),
                    ("取引通番", "transaction_number"),
                ],
            ),
            (
                "その他",
                [
                    ("発行日", "issued_at"),
                    ("有効期限", "expires_at"),
                    ("発行駅", "issued_station"),
                    ("定期区間", "commuter_pass"),
                ],
            ),
        ]

        for title, items in sections:
            section_frame = self._create_section(
                frame,
                title,
                padding=(12, 8, 12, 8),
                margin=(0, 12),
            )
            section_frame.columnconfigure(1, weight=1)
            self._populate_label_value_grid(
                section_frame,
                items,
                self.summary_vars,
                label_width=12,
                wraplength=640,
                label_style="SummaryKey.TLabel",
                value_style="SummaryValue.TLabel",
            )

    def _build_issue_tab(self, frame: ttk.Frame) -> None:
        commuter_frame = self._create_section(
            frame,
            "定期券詳細",
            padding=(12, 8, 12, 8),
            margin=(0, 12),
        )
        commuter_frame.columnconfigure(1, weight=1)

        commuter_labels = [
            ("開始日", "valid_from"),
            ("終了日", "valid_to"),
            ("始点駅", "start_station"),
            ("終点駅", "end_station"),
            ("経由駅1", "via1"),
            ("経由駅2", "via2"),
            ("発行日", "issued_at"),
        ]

        self._populate_label_value_grid(
            commuter_frame,
            commuter_labels,
            self.commuter_detail_vars,
            label_width=12,
            wraplength=640,
        )

        issue_container = self._create_section(
            frame,
            "発行関連情報",
            padding=(12, 12, 12, 12),
            margin=(0, 12),
        )

        for section_title, fields in self.issue_detail_sections:
            section_frame = self._create_section(
                issue_container,
                section_title,
                padding=(10, 6, 10, 6),
                margin=(0, 8),
                variant="embedded",
            )
            section_frame.columnconfigure(1, weight=1)
            self._populate_label_value_grid(
                section_frame,
                fields,
                self.issue_detail_vars,
                label_width=16,
                wraplength=660,
            )

    def _build_history_tab(self, frame: ttk.Frame) -> None:
        search_frame = ttk.Frame(frame, padding=(0, 0, 0, 8), style="Main.TFrame")
        search_frame.pack(fill=tk.X, pady=(0, 12))
        search_frame.columnconfigure(1, weight=1)

        ttk.Label(search_frame, text="フィルター", style="Meta.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        filter_entry = ttk.Entry(
            search_frame,
            textvariable=self.history_filter_var,
        )
        filter_entry.grid(row=0, column=1, sticky="ew", padx=(8, 8))
        self.history_filter_entry = filter_entry
        ttk.Button(
            search_frame,
            text="クリア",
            command=self._clear_history_filter,
        ).grid(row=0, column=2, sticky="e")

        history_container = self._create_section(
            frame,
            "取引履歴",
            padding=(4, 4, 4, 4),
            margin=(0, 0),
            fill="both",
            expand=True,
        )

        history_columns = [
            TreeColumnSpec("日時", 200),
            TreeColumnSpec("取引種別", 180),
            TreeColumnSpec("支払種別", 200),
            TreeColumnSpec("改札処理", 200),
            TreeColumnSpec("入場駅", 260),
            TreeColumnSpec("出場駅", 260),
            TreeColumnSpec("残高", 120, "e"),
            TreeColumnSpec("機器", 180),
            TreeColumnSpec("通番", 120, "e"),
        ]
        self.history_tree = self._create_treeview(
            history_container,
            history_columns,
            odd_row_color="#f5f7fb",
        )

        self.history_filter_var.trace_add("write", self._apply_history_filter)

    def _build_gate_tab(self, frame: ttk.Frame) -> None:
        gate_container = self._create_section(
            frame,
            "改札入出場履歴",
            padding=(4, 4, 4, 4),
            margin=(0, 12),
            fill="both",
            expand=True,
        )

        gate_columns = [
            TreeColumnSpec("日時", 200),
            TreeColumnSpec("入出場種別", 200),
            TreeColumnSpec("中間処理", 200),
            TreeColumnSpec("駅", 280),
            TreeColumnSpec("装置番号", 140, "center"),
            TreeColumnSpec("金額", 140, "e"),
            TreeColumnSpec("定期運賃", 140, "e"),
            TreeColumnSpec("定期駅", 200),
        ]
        self.gate_tree = self._create_treeview(
            gate_container,
            gate_columns,
            odd_row_color="#f5fbf7",
        )

        sf_frame = self._create_section(
            frame,
            "SF改札入場情報",
            padding=(12, 8, 12, 8),
            margin=(0, 12),
        )
        sf_frame.columnconfigure(1, weight=1)

        sf_labels = [
            ("入場駅", "entry_station"),
            ("中間改札入場駅", "intermediate_entry"),
            ("中間改札入場日付", "intermediate_entry_date"),
            ("中間改札入場時刻", "intermediate_entry_time"),
            ("中間改札出場駅", "intermediate_exit"),
            ("中間改札出場時刻", "intermediate_exit_time"),
            ("不明値1", "unknown_value1"),
            ("不明値2", "unknown_value2"),
        ]

        self._populate_label_value_grid(
            sf_frame,
            sf_labels,
            self.sf_gate_vars,
            label_width=14,
            wraplength=460,
            padx=(0, 8),
            pady=2,
        )

    def _build_misc_tab(self, frame: ttk.Frame) -> None:
        misc_container = self._create_section(
            frame,
            "不明な情報",
            padding=(12, 8, 12, 8),
            margin=(0, 12),
        )
        misc_container.columnconfigure(1, weight=1)

        self._populate_label_value_grid(
            misc_container,
            self.misc_detail_fields,
            self.misc_detail_vars,
            label_width=14,
        )

    def _build_details_tab(self, frame: ttk.Frame) -> None:
        details_container = self._create_section(
            frame,
            "カード情報 JSON",
            padding=(12, 12, 12, 12),
            margin=(0, 12),
            fill="both",
            expand=True,
        )

        toolbar = ttk.Frame(details_container, style="SectionInner.TFrame")
        toolbar.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(toolbar, text="操作", style="SectionMeta.TLabel").pack(side=tk.LEFT)

        button_row = ttk.Frame(toolbar, style="SectionInner.TFrame")
        button_row.pack(side=tk.RIGHT)

        self.copy_details_button = ttk.Button(
            button_row,
            text="JSONをコピー",
            command=self._copy_details_to_clipboard,
            state=tk.DISABLED,
        )
        self.copy_details_button.pack(side=tk.LEFT)

        self.export_details_button = ttk.Button(
            button_row,
            text="JSONを書き出し…",
            command=self._export_details_to_file,
            state=tk.DISABLED,
        )
        self.export_details_button.pack(side=tk.LEFT, padx=(8, 0))

        text_container = ttk.Frame(details_container, style="SectionInner.TFrame")
        text_container.pack(fill=tk.BOTH, expand=True)
        text_container.columnconfigure(0, weight=1)
        text_container.rowconfigure(0, weight=1)

        self.details_text = tk.Text(text_container, wrap=tk.NONE)
        self.details_text.configure(state=tk.DISABLED, font=("TkFixedFont", 11))

        y_scroll = ttk.Scrollbar(
            text_container, orient=tk.VERTICAL, command=self.details_text.yview
        )
        x_scroll = ttk.Scrollbar(
            text_container, orient=tk.HORIZONTAL, command=self.details_text.xview
        )
        self.details_text.configure(
            xscrollcommand=x_scroll.set, yscrollcommand=y_scroll.set
        )

        self.details_text.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

    def _copy_details_to_clipboard(self) -> None:
        if not self.current_card_json:
            messagebox.showinfo("カード情報なし", "カード情報が読み込まれていません。")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(self.current_card_json)
        self.root.update_idletasks()
        self._update_status("カード詳細をクリップボードにコピーしました。")

    def _export_details_to_file(self) -> None:
        if not self.current_card_json:
            messagebox.showinfo("カード情報なし", "カード情報が読み込まれていません。")
            return

        file_path = filedialog.asksaveasfilename(
            title="カード情報を書き出し",
            defaultextension=".json",
            filetypes=[
                ("JSON ファイル", "*.json"),
                ("すべてのファイル", "*.*"),
            ],
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as output_file:
                output_file.write(self.current_card_json)
        except OSError as exc:
            messagebox.showerror(
                "書き出しエラー", f"ファイルに保存できませんでした: {exc}"
            )
            return

        self._update_status(f"カード情報を書き出しました: {file_path}")

    def _clear_history_filter(self) -> None:
        if self.history_filter_var.get():
            self.history_filter_var.set("")
        else:
            self._apply_history_filter()

    def _apply_history_filter(self, *_: Any) -> None:
        tree = self.history_tree
        if tree is None:
            return
        if not tree.get_children() and not self.current_history:
            return

        query = self.history_filter_var.get().strip().lower()
        if not self.current_history:
            tree.delete(*tree.get_children())
            return

        if not query:
            self._render_history_rows(self.current_history)
            return

        filtered = [
            entry
            for entry in self.current_history
            if any(
                query in str(entry.get(field, "")).lower()
                for field in HISTORY_FILTER_FIELDS
            )
            or query in str(entry.get("transaction_time", "")).lower()
            or query in str(entry.get("balance", "")).lower()
            or query in str(entry.get("transaction_number", "")).lower()
        ]
        self._render_history_rows(filtered)

    def _render_history_rows(self, rows: list[dict[str, Any]]) -> None:
        if self.history_tree is None:
            return

        self.history_tree.delete(*self.history_tree.get_children())

        for index, entry in enumerate(rows):
            entry_station = entry.get("entry_station", "-")
            exit_station = entry.get("exit_station", "-")
            if entry.get("transaction_type_code") == 0x46:
                entry_station = "—"
                exit_station = "—"

            transaction_number_display = self._format_integer(
                entry.get("transaction_number")
            )

            values = (
                f"{entry['recorded_on']} {entry.get('transaction_time', '')}".strip(),
                entry.get("transaction_type", "-"),
                entry.get("pay_type", "-"),
                entry.get("gate_instruction_type", "-"),
                entry_station,
                exit_station,
                self._format_currency(entry.get("balance")),
                entry.get("recorded_by", "-"),
                transaction_number_display,
            )
            tag = "odd" if index % 2 else "even"
            self.history_tree.insert("", tk.END, values=values, tags=(tag,))

    def _focus_history_filter(self, event: Any | None = None) -> str | None:
        if self.history_filter_entry is None:
            return None

        self.history_filter_entry.focus_set()
        self.history_filter_entry.selection_range(0, tk.END)
        return "break"

    def _nfc_loop(self) -> None:
        self._reset_progress()
        self._update_status("NFC リーダーを初期化しています…")

        try:
            with nfc.ContactlessFrontend("usb") as clf:
                self._update_status("カードをかざしてください。")
                self._reset_progress()
                while True:
                    try:
                        clf.connect(
                            rdwr={
                                "targets": ["212F", "424F"],
                                "on-connect": self._on_connect,
                            }
                        )
                    except Exception as exc:
                        self._reset_progress()
                        self._update_status(f"読み取りエラー: {exc}")
        except IOError as exc:
            self._reset_progress()
            self._update_status(f"NFC リーダーを初期化できません: {exc}")

    def _on_connect(self, tag: Tag) -> bool:
        self._reset_progress()
        if not isinstance(tag, FelicaStandard):
            self._update_status("FeliCa 以外のタグを検出しました。")
            return True

        self._update_status("カード情報を取得しています…")
        self._set_progress(5.0)

        try:
            card_data = self._collect_card_data(tag)
        except FelicaRemoteClientError as exc:
            self._reset_progress()
            self._update_status(f"サーバ通信エラー: {exc}")
            return True
        except Exception as exc:
            self._reset_progress()
            self._update_status(f"カード情報の取得に失敗しました: {exc}")
            return True

        self.root.after(0, self._apply_card_data, card_data)
        return True

    def _collect_card_data(self, tag: FelicaStandard) -> CardData:
        polling_result = tag.polling(SYSTEM_CODE)
        if len(polling_result) != 2:
            raise RuntimeError("Polling 応答が不正です。")
        tag.idm, tag.pmm = polling_result
        self._set_progress(15.0)

        client = self._get_remote_client(tag)
        if self.card_data_service is None:
            raise RuntimeError("カードデータサービスが初期化されていません。")

        return self.card_data_service.collect(
            client,
            progress_callback=self._set_progress,
        )

    def _format_currency(self, value: Any) -> str:
        return f"{value:,} 円" if isinstance(value, int) else "-"

    def _format_integer(self, value: Any) -> str:
        return f"{value:,}" if isinstance(value, int) else "-"

    def _format_region(self, region_code: Any) -> str:
        if isinstance(region_code, int):
            return f"{region_code} (0x{region_code:02X})"
        return "-"

    def _format_hex_clock(self, value: Any) -> str:
        if isinstance(value, str) and len(value) >= 4:
            return f"{value[0:2]}:{value[2:4]}"
        return "-"

    def _update_summary(
        self,
        system_info: SystemInfo,
        issue_primary: dict[str, Any],
        issue_secondary: dict[str, Any],
        attribute_info: dict[str, Any],
        commuter_info: dict[str, Any],
    ) -> None:
        self.summary_vars["idi"].set(system_info.idi_display)
        self.summary_vars["pmi"].set(system_info.pmi)
        self.summary_vars["owner_name"].set(issue_primary.get("owner_name", "-"))
        self.summary_vars["card_type"].set(attribute_info.get("card_type", "-"))
        self.summary_vars["balance"].set(
            self._format_currency(attribute_info.get("balance"))
        )
        self.summary_vars["region"].set(
            self._format_region(attribute_info.get("region"))
        )
        self.summary_vars["deposit"].set(
            self._format_currency(issue_primary.get("deposit"))
        )
        self.summary_vars["initial_amount"].set(
            self._format_currency(issue_secondary.get("initial_amount"))
        )
        self.summary_vars["issued_at"].set(issue_primary.get("issued_at", "-"))
        self.summary_vars["expires_at"].set(issue_primary.get("expires_at", "-"))
        self.summary_vars["issued_station"].set(
            issue_primary.get("issued_station", "-")
        )
        self.summary_vars["transaction_number"].set(
            self._format_integer(attribute_info.get("transaction_number"))
        )

        start_station = commuter_info.get("start_station")
        end_station = commuter_info.get("end_station")
        if start_station and end_station:
            commuter_summary = f"{start_station} → {end_station}"
        else:
            commuter_summary = "-"
        self.summary_vars["commuter_pass"].set(commuter_summary)

    def _update_commuter_details(self, commuter_info: dict[str, Any]) -> None:
        field_mapping = {
            "valid_from": "valid_from",
            "valid_to": "valid_to",
            "start_station": "start_station",
            "end_station": "end_station",
            "via1": "via1_station",
            "via2": "via2_station",
            "issued_at": "issued_at",
        }
        for target_key, source_key in field_mapping.items():
            value = commuter_info.get(source_key)
            display = "-" if value in (None, "") else str(value)
            self.commuter_detail_vars[target_key].set(display)

    def _apply_card_data(self, card_data: CardData) -> None:
        system_info = card_data.system
        issue_primary = card_data.issue_primary
        issue_secondary = card_data.issue_secondary
        attribute_info = card_data.attribute
        commuter_info = card_data.commuter

        self._update_summary(
            system_info,
            issue_primary,
            issue_secondary,
            attribute_info,
            commuter_info,
        )
        self._update_commuter_details(commuter_info)
        self._populate_issue_details(
            issue_primary,
            issue_secondary,
            attribute_info,
            card_data.unknown,
        )
        self._populate_history(card_data.transaction_history)
        self._populate_gate_info(card_data.gate, card_data.sf_gate)
        self._populate_details(card_data)
        self._finalize_card_update()

    def _populate_issue_details(
        self,
        issue_primary: dict[str, Any],
        issue_secondary: dict[str, Any],
        attribute_info: dict[str, Any],
        unknown_info: dict[str, Any],
    ) -> None:
        region_display = self._format_region(attribute_info.get("region"))
        attribute_txn_display = self._format_integer(
            attribute_info.get("transaction_number")
        )
        unknown_balance_display = self._format_currency(unknown_info.get("balance"))
        unknown_txn_display = self._format_integer(
            unknown_info.get("transaction_number")
        )

        detail_values: dict[str, Any] = {
            "owner_name": issue_primary.get("owner_name", "-"),
            "owner_phone_hex": issue_primary.get("owner_phone_hex", "-"),
            "owner_age_code": issue_primary.get("owner_age_code", "-"),
            "owner_birthdate": issue_primary.get("owner_birthdate", "-"),
            "secondary_issue_id": issue_primary.get("secondary_issue_id", "-"),
            "issuer_id": issue_primary.get("issuer_id", "-"),
            "deposit": self._format_currency(issue_primary.get("deposit")),
            "issued_by": issue_primary.get("issued_by", "-"),
            "issued_station": issue_primary.get("issued_station", "-"),
            "issued_at": issue_primary.get("issued_at", "-"),
            "expires_at": issue_primary.get("expires_at", "-"),
            "issued_by_detail": issue_secondary.get("issued_by", "-"),
            "issued_station_detail": issue_secondary.get("issued_station", "-"),
            "initial_amount": self._format_currency(
                issue_secondary.get("initial_amount")
            ),
            "card_type": attribute_info.get("card_type", "-"),
            "region_display": region_display,
            "attribute_transaction_number": attribute_txn_display,
            "attribute_balance": self._format_currency(attribute_info.get("balance")),
        }

        for _, fields in self.issue_detail_sections:
            for _, key in fields:
                self.issue_detail_vars[key].set(detail_values.get(key, "-"))

        self.misc_detail_vars["unknown_balance"].set(unknown_balance_display)
        self.misc_detail_vars["unknown_date"].set(unknown_info.get("date", "-"))
        self.misc_detail_vars["unknown_transaction_number"].set(unknown_txn_display)

    def _populate_gate_info(
        self,
        gate_entries: list[dict[str, Any]],
        sf_gate_info: dict[str, Any],
    ) -> None:
        if self.gate_tree is None:
            return

        self.gate_tree.delete(*self.gate_tree.get_children())
        self.current_gate_entries = gate_entries
        if sf_gate_info is None:
            sf_gate_info = {}

        for index, entry in enumerate(gate_entries):
            date_value = entry.get("date")
            timestamp = date_value if isinstance(date_value, str) else "-"
            time_value = entry.get("time")
            if isinstance(time_value, str) and time_value:
                timestamp = f"{timestamp} {time_value}".strip()
            timestamp = timestamp.strip()
            values = (
                timestamp,
                entry.get("gate_in_out_type", "-"),
                entry.get("intermediate_gate_instruction_type", "-"),
                entry.get("station", "-"),
                entry.get("device_id_hex", "-"),
                self._format_currency(entry.get("amount")),
                self._format_currency(entry.get("commuter_pass_fee")),
                entry.get("commuter_station", "-"),
            )
            tag = "odd" if index % 2 else "even"
            self.gate_tree.insert("", tk.END, values=values, tags=(tag,))

        self.sf_gate_vars["entry_station"].set(sf_gate_info.get("entry_station", "-"))
        self.sf_gate_vars["intermediate_entry"].set(
            sf_gate_info.get("intermediate_entry_station", "-")
        )
        self.sf_gate_vars["intermediate_entry_date"].set(
            sf_gate_info.get("intermediate_entry_date", "-")
        )
        self.sf_gate_vars["intermediate_entry_time"].set(
            self._format_hex_clock(sf_gate_info.get("intermediate_entry_time"))
        )
        self.sf_gate_vars["intermediate_exit"].set(
            sf_gate_info.get("intermediate_exit_station", "-")
        )
        self.sf_gate_vars["intermediate_exit_time"].set(
            self._format_hex_clock(sf_gate_info.get("intermediate_exit_time"))
        )
        self.sf_gate_vars["unknown_value1"].set(
            sf_gate_info.get("unknown_value1_hex", "-")
        )
        self.sf_gate_vars["unknown_value2"].set(
            sf_gate_info.get("unknown_value2_hex", "-")
        )

    def _populate_history(self, history: list[dict[str, Any]]) -> None:
        self.current_history = history
        self._apply_history_filter()

    def _populate_details(self, card_data: CardData) -> None:
        if self.details_text is None:
            return

        serializable_data = card_data.to_serializable_dict()
        text = json.dumps(serializable_data, ensure_ascii=False, indent=2)
        self.details_text.configure(state=tk.NORMAL)
        self.details_text.delete("1.0", tk.END)
        self.details_text.insert("1.0", text)
        self.details_text.configure(state=tk.DISABLED)
        self.current_card_json = text

        if self.copy_details_button is not None:
            self.copy_details_button.configure(state=tk.NORMAL)
        if self.export_details_button is not None:
            self.export_details_button.configure(state=tk.NORMAL)

    def _finalize_card_update(self) -> None:
        self.last_updated_var.set(f"最終更新: {self._current_local_timestamp()}")
        self._update_status("カード情報を更新しました。カードを離してください。")
        self._set_progress(100.0)

    def _set_progress(self, value: float) -> None:
        clamped = max(0.0, min(100.0, value))
        self.root.after(0, self.progress_var.set, clamped)

    def _reset_progress(self) -> None:
        self._set_progress(0.0)

    def _update_status(self, message: str) -> None:
        self.root.after(0, self.status_var.set, message)

    def _current_local_timestamp(self) -> str:
        local_time = datetime.now().astimezone()
        return local_time.strftime("%Y-%m-%d %H:%M:%S %Z")

    def _on_close(self) -> None:
        if self._remote_client is not None:
            self._remote_client.close()
            self._remote_client = None
        self.root.quit()

    def run(self) -> None:
        self.root.mainloop()


def fix_ic_code_map():
    FelicaStandard.IC_CODE_MAP[0x31] = ("RC-S???", 1, 1)


def main() -> None:
    fix_ic_code_map()

    app = SuicaGuiApp()
    app.run()


if __name__ == "__main__":
    main()
