import csv
from .station_code_lookup import StationCodeLookup


EQUIPMENT_TYPES: dict[int, str] = {
    0x00: "未定義",
    0x03: "のりこし精算機",
    0x04: "携帯端末",
    0x05: "バス等車載機",
    0x07: "カード発売機",
    0x08: "自動券売機",
    0x09: "SMART ICOCA クイックチャージ機?",
    0x12: "自動券売機(東京モノレール)",
    0x14: "駅務機器(PASMO発行機?)",
    0x15: "定期券発売機",
    0x16: "自動改札機",
    0x17: "簡易改札機",
    0x18: "駅務機器(発行機?)",
    0x19: "窓口処理機(みどりの窓口)",
    0x1A: "窓口処理機(有人改札)",
    0x1B: "モバイルFeliCa",
    0x1C: "入場券券売機",
    0x1D: "他社乗換自動改札機",
    0x1F: "入金機",
    0x20: "発行機?(モノレール)",
    0x22: "簡易改札機(ことでん)",
    0x34: "カード発売機(せたまる?)",
    0x35: "バス等車載機(せたまる車内入金機?)",
    0x36: "バス等車載機(車内簡易改札機)",
    0x46: "ビューアルッテ端末",
    0xC7: "物販端末",
    0xC8: "物販端末",
}

TRANSACTION_TYPES: dict[int, str] = {
    0x00: "未定義",
    0x01: "自動改札機出場",
    0x02: "SFチャージ",
    0x03: "きっぷ購入",
    0x04: "磁気券精算",
    0x05: "乗越精算",
    0x06: "窓口出場",
    0x07: "新規",
    0x08: "控除",
    0x0D: "バス等均一運賃",
    0x0F: "バス等",
    0x11: "再発行?",
    0x13: "料金出場",
    0x14: "オートチャージ",
    0x1F: "バス等チャージ",
    0x46: "物販",
    0x48: "ポイントチャージ",
    0x4B: "入場・物販",
}

PAY_TYPES: dict[int, str] = {
    0x00: "現金/なし",
    0x02: "VIEW",
    0x0B: "PiTaPa",
    0x0D: "オートチャージ対応PASMO",
    0x3F: "モバイルSuica(VIEW決済以外)",
}

GATE_INSTRUCTION_TYPES: dict[int, str] = {
    0x00: "未定義",
    0x01: "入場",
    0x02: "入場/出場",
    0x03: "定期入場/出場",
    0x04: "入場/定期出場",
    0x0E: "窓口出場",
    0x0F: "入場/出場(バス等)",
    0x12: "料金定期入場/料金出場",
    0x17: "入場/出場(乗継割引)",
    0x21: "入場/出場(バス等乗継割引)",
}

CARD_TYPE_LABELS: dict[int, str] = {
    0: "せたまる/IruCa",
    2: "Suica/PiTaPa/TOICA/PASMO",
    3: "ICOCA",
}

GATE_IN_OUT_TYPES: dict[int, str] = {
    0x00: "精算出場",
    0x01: "精算出場(プリペイドカード併用?)",
    0x20: "出場",
    0x21: "駅務機器出場",
    0x22: "割引出場",
    0x24: "割引出場?",
    0x40: "定期出場",
    0x80: "均一区間入場?",
    0xA0: "入場",
    0xA2: "割引入場?",
    0xC0: "定期入場",
}

INTERMADIATE_GATE_INSTRUCTION_TYPES: dict[int, str] = {
    0x00: "未定義",
    0x04: "乗継割引?",
    0x08: "電車バス乗継割引?",
    0x40: "新幹線中間改札?",
}

SYSTEM_CODE = 0x0003


def load_keys_from_csv(
    system_code: int, csv_file: str = "keys.csv"
) -> dict[int, bytes]:
    """Load keys from CSV file and return a dictionary mapping node IDs to keys."""

    keys: dict[int, bytes] = {}
    try:
        with open(csv_file, "r") as file:
            reader = csv.DictReader(file)
            for row in reader:
                row_system_code = int(row["system_code"], 16)
                if row_system_code != system_code:
                    continue

                node_id = int(row["node"], 16)
                keys[node_id] = bytes.fromhex(row["key"])
    except FileNotFoundError:
        print(f"Warning: {csv_file} not found.")
        return {}
    except Exception as exc:
        print(f"Error reading {csv_file}: {exc}")
        return {}
    return keys


def _lookup_by_mapping(mapping: dict[int, str], value: int, unknown_label: str) -> str:
    return mapping.get(value, f"不明な{unknown_label} (0x{value:02X})")


def equipment_type_to_str(equipment_type: int) -> str:
    return _lookup_by_mapping(EQUIPMENT_TYPES, equipment_type, "機器種別")


def transaction_type_to_str(transaction_type: int) -> str:
    return _lookup_by_mapping(TRANSACTION_TYPES, transaction_type, "取引種別")


def pay_type_to_str(pay_type: int) -> str:
    return _lookup_by_mapping(PAY_TYPES, pay_type, "支払種別")


def gate_instruction_type_to_str(gate_instruction_type: int) -> str:
    return _lookup_by_mapping(
        GATE_INSTRUCTION_TYPES, gate_instruction_type, "改札処理種別"
    )


def gate_in_out_type_to_str(gate_instruction_type: int) -> str:
    return _lookup_by_mapping(
        GATE_IN_OUT_TYPES, gate_instruction_type, "改札入出場種別"
    )


def intermadiate_gate_instruction_type_to_str(gate_instruction_type: int) -> str:
    return _lookup_by_mapping(
        INTERMADIATE_GATE_INSTRUCTION_TYPES,
        gate_instruction_type,
        "中間改札処理種別",
    )


def int_to_date(value: int) -> tuple[int, int, int]:
    year = value >> 9
    month = (value >> 5) & 0x0F
    day = value & 0x1F
    return year, month, day


def int_to_time(value: int) -> tuple[int, int, int]:
    hour = value >> 11
    minute = (value >> 5) & 0x3F
    second = (value & 0x1F) * 2
    return hour, minute, second


def format_date(value: int) -> str:
    year, month, day = int_to_date(value)
    return f"{year:02}-{month:02}-{day:02}"


def format_time(value: int) -> str:
    hour, minute, second = int_to_time(value)
    return f"{hour:02}:{minute:02}:{second:02}"


def format_station(
    station_code_lookup: StationCodeLookup,
    line_code: int,
    station_order: int,
) -> str:
    station = station_code_lookup.get_station_info(line_code, station_order)
    if station is None:
        return (
            f"不明 (線区コード: 0x{line_code:02X}, 駅順コード: 0x{station_order:02X})"
        )

    company = station["company_name"]
    line = station["line_name"]
    name = station["station_name"]
    return f"{company} {line} {name}"


def idi_bytes_to_str(idi_bytes: bytes) -> str:
    """Convert an 8-byte IDi to its string form."""

    if len(idi_bytes) < 8:
        raise ValueError("idi_bytes must be 8 bytes.")
    data = bytes(idi_bytes)

    head = data[0:4].hex().upper()

    v = (data[4] << 8) | data[5]
    year = (v >> 9) & 0x3F
    month = (v >> 5) & 0x0F
    day = v & 0x1F
    yy = year % 100
    date_part = f"{yy:02d}{month:02d}{day:02d}"

    tail_val = int.from_bytes(data[6:8], byteorder="big")
    tail = f"{tail_val:05d}"

    return f"{head}{date_part}{tail}"
