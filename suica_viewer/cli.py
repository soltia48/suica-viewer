import os
from collections.abc import Iterable

import nfc
from nfc.clf import RemoteTarget
from nfc.tag import Tag
from nfc.tag.tt3_sony import FelicaStandard

from .auth_client import FelicaRemoteClient, FelicaRemoteClientError
from .utils import (
    CARD_TYPE_LABELS,
    SYSTEM_CODE,
    equipment_type_to_str,
    format_date,
    format_station,
    format_time,
    gate_in_out_type_to_str,
    gate_instruction_type_to_str,
    idi_bytes_to_str,
    intermadiate_gate_instruction_type_to_str,
    issuer_id_to_str,
    pay_type_to_str,
    transaction_type_to_str,
)
from .station_code_lookup import StationCodeLookup

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


class RemoteCardReader:
    """Read encrypted blocks via the remote server."""

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


def resolve_server_url() -> str:
    value = os.environ.get("AUTH_SERVER_URL", "").strip()
    return value or DEFAULT_AUTH_SERVER_URL


def print_section(title: str, *, leading_newline: bool = True) -> None:
    if leading_newline:
        print()
    print(title)
    print("-" * len(title))


def print_item(label: str, value: object) -> None:
    print(f"  - {label}: {value}")


class SuicaTagReporter:
    """Encapsulates the various Suica information dump routines."""

    def __init__(
        self,
        reader: RemoteCardReader,
        station_code_lookup: StationCodeLookup,
    ) -> None:
        self.reader = reader
        self.station_code_lookup = station_code_lookup

    def _format_station(self, line_code: int, station_order: int) -> str:
        return format_station(self.station_code_lookup, line_code, station_order)

    def _read_blocks(self, service_index: int, indexes: Iterable[int]) -> list[bytes]:
        return self.reader.read_blocks(service_index, indexes)

    def _read_single_block(self, service_code: int, index: int) -> bytes:
        return self._read_blocks(service_code, [index])[0]

    def print_issue_information(self, *, leading_newline: bool = True) -> None:
        print_section("発行情報", leading_newline=leading_newline)
        owner_block, personal_block, secondary_idi_block, metadata_block = (
            self._read_blocks(0, range(4))
        )

        name = owner_block.decode("shift_jis").rstrip()
        print_item("所有者名", name)
        print_item("第二発行ID", idi_bytes_to_str(secondary_idi_block))

        phone_number = personal_block[0:8].hex().rstrip("f")
        print_item("所有者電話番号", phone_number)

        age = personal_block[8:9].hex()
        print_item("所有者年齢", age)

        dob = int.from_bytes(personal_block[9:11], byteorder="big")
        print_item("所有者生年月日", format_date(dob))

        deposit = int.from_bytes(personal_block[12:14], byteorder="little")
        print_item("デポジット額", f"{deposit} 円")

        issuer_id_hex = metadata_block[0:2].hex().upper()
        print_item("発行者ID", issuer_id_to_str(issuer_id_hex))

        issued_by = metadata_block[2]
        print_item("発行機器", equipment_type_to_str(issued_by))

        issued_station_line = metadata_block[3]
        issued_station_order = metadata_block[4]
        issued_station = self._format_station(issued_station_line, issued_station_order)
        print_item("発行駅", issued_station)

        issued_at = int.from_bytes(metadata_block[7:9], byteorder="big")
        print_item("発行日", format_date(issued_at))

        expires_at = int.from_bytes(metadata_block[14:16], byteorder="big")
        print_item("有効期限", format_date(expires_at))

    def print_attribute_information(self) -> None:
        print_section("属性情報")
        block = self._read_single_block(1, 0)

        card_type = block[8] >> 4
        card_type_str = CARD_TYPE_LABELS.get(card_type, "不明")
        print_item("カード種別", card_type_str)

        region = block[8] & 0x0F
        print_item("地域", region)

        amount = int.from_bytes(block[11:13], byteorder="little")
        print_item("残高", f"{amount} 円")

        transaction_number = int.from_bytes(block[14:16], byteorder="big")
        print_item("取引通番", transaction_number)

    def print_unknown_information(self) -> None:
        print_section("？？情報")
        block = self._read_single_block(2, 0)

        amount = int.from_bytes(block[0:2], byteorder="little")
        print_item("不明な残高", f"{amount} 円")

        issued_at = int.from_bytes(block[8:10], byteorder="big")
        print_item("不明な日付", format_date(issued_at))

        transaction_number = int.from_bytes(block[14:16], byteorder="big")
        print_item("不明な取引通番", transaction_number)

    def print_last_topup_information(self) -> None:
        print_section("最終チャージ情報")
        detail_block, *_ = self._read_blocks(3, range(3))

        topup_by = detail_block[0]
        print_item("チャージ機器", equipment_type_to_str(topup_by))

        topup_station_line = detail_block[1]
        topup_station_order = detail_block[2]
        topup_station = self._format_station(topup_station_line, topup_station_order)
        print_item("チャージ駅", topup_station)

        topup_amount = int.from_bytes(detail_block[5:7], byteorder="little")
        print_item("チャージ金額", f"{topup_amount} 円")

    def _print_transaction_entry(
        self,
        index: int,
        recorded_by: int,
        transaction_type: int,
        pay_type: int,
        gate_instruction_type: int,
        recorded_at: int,
        block: bytes,
    ) -> None:
        print(f"[{index:02}] {format_date(recorded_at)}")
        print_item("機器", equipment_type_to_str(recorded_by))
        print_item("取引種別", transaction_type_to_str(transaction_type))
        print_item("支払種別", pay_type_to_str(pay_type))
        print_item("改札処理", gate_instruction_type_to_str(gate_instruction_type))

        if transaction_type == 0x46:
            time_value = int.from_bytes(block[6:8], byteorder="big")
            print_item("取引時刻", format_time(time_value))
        else:
            entry_station_line = block[6]
            entry_station_order = block[7]
            exit_station_line = block[8]
            exit_station_order = block[9]
            print_item(
                "入場駅",
                self._format_station(entry_station_line, entry_station_order),
            )
            print_item(
                "出場駅",
                self._format_station(exit_station_line, exit_station_order),
            )

        amount = int.from_bytes(block[10:12], byteorder="little")
        transaction_number = int.from_bytes(block[13:15], byteorder="big")
        print_item("残高", f"{amount} 円")
        print_item("取引通番", transaction_number)
        print()

    def print_transaction_history(self) -> None:
        print_section("取引履歴")
        blocks = self._read_blocks(4, range(20))

        for index, block in enumerate(blocks):
            recorded_by = block[0]
            if recorded_by == 0x00:
                break

            transaction_type = block[1] & 0x7F
            pay_type = block[2]
            gate_instruction_type = block[3]
            recorded_at = int.from_bytes(block[4:6], byteorder="big")

            self._print_transaction_entry(
                index,
                recorded_by,
                transaction_type,
                pay_type,
                gate_instruction_type,
                recorded_at,
                block,
            )

    def print_unknown_blocks(self) -> None:
        print_section("不明情報1")
        blocks = self._read_blocks(5, range(10))
        for block in blocks:
            print(block.hex())

    def print_commuter_pass_information(self) -> None:
        print_section("定期情報")
        primary_block, _, supplemental_block = self._read_blocks(6, range(3))

        start_at = int.from_bytes(primary_block[0:2], byteorder="big")
        print_item("開始日", format_date(start_at))

        end_at = int.from_bytes(primary_block[2:4], byteorder="big")
        print_item("終了日", format_date(end_at))

        start_station = self._format_station(primary_block[8], primary_block[9])
        print_item("始点駅", start_station)

        end_station = self._format_station(primary_block[10], primary_block[11])
        print_item("終点駅", end_station)

        via1_station = self._format_station(primary_block[12], primary_block[13])
        print_item("経由駅1", via1_station)

        via2_station = self._format_station(primary_block[14], primary_block[15])
        print_item("経由駅2", via2_station)

        issued_at = int.from_bytes(supplemental_block[5:7], byteorder="big")
        print_item("発行日", format_date(issued_at))

    def print_gate_in_out_information(self) -> None:
        print_section("改札入出場情報")
        blocks = self._read_blocks(7, range(3))

        for index, block in enumerate(blocks):
            date = int.from_bytes(block[6:8], byteorder="big")
            time_hex = block[8:10].hex()
            print(f"[{index:02}] {format_date(date)} {time_hex[0:2]}:{time_hex[2:4]}")

            gate_in_out_type = gate_in_out_type_to_str(block[0])
            print_item("改札入出場種別", gate_in_out_type)

            intermadiate_gate_instruction_type = (
                intermadiate_gate_instruction_type_to_str(block[1])
            )
            print_item("中間改札処理種別", intermadiate_gate_instruction_type)

            station_line = block[2]
            station_order = block[3]
            print_item("入出場駅", self._format_station(station_line, station_order))

            print_item("装置番号", block[4:6].hex().upper())

            amount = int.from_bytes(block[10:12], byteorder="little")
            print_item("金額", f"{amount} 円")

            commuter_pass_fee = int.from_bytes(block[12:14], byteorder="little")
            print_item("最寄定期区間までの運賃", commuter_pass_fee)

            station_line = block[14]
            station_order = block[15]
            print_item(
                "最寄定期区間の駅",
                self._format_station(station_line, station_order),
            )

            print()

    def print_sf_gate_in_information(self) -> None:
        print_section("SF改札入場情報")
        first_block, second_block = self._read_blocks(8, range(2))

        entry_station_line = first_block[0]
        entry_station_order = first_block[1]
        print_item(
            "入場駅",
            self._format_station(entry_station_line, entry_station_order),
        )

        print_item(
            "料金収受対象中間改札入出場日付",
            format_date(int.from_bytes(second_block[0:2], byteorder="big")),
        )
        entry_time = second_block[2:4].hex()
        print_item("中間改札入場時刻", f"{entry_time[0:2]}:{entry_time[2:4]}")

        intermadiate_entry_station_line = second_block[4]
        intermadiate_entry_station_order = second_block[5]
        print_item(
            "中間改札入場駅",
            self._format_station(
                intermadiate_entry_station_line, intermadiate_entry_station_order
            ),
        )

        print_item("不明値1", hex(second_block[6]))

        exit_time = second_block[7:9].hex()
        print_item("中間改札出場時刻", f"{exit_time[0:2]}:{exit_time[2:4]}")

        intermadiate_exit_station_line = second_block[9]
        intermadiate_exit_station_order = second_block[10]
        print_item(
            "中間改札出場駅",
            self._format_station(
                intermadiate_exit_station_line, intermadiate_exit_station_order
            ),
        )

        print_item("不明値2", hex(second_block[11]))


def on_startup(target: list[RemoteTarget]) -> list[RemoteTarget]:
    return target


def on_connect(tag: Tag):
    if not isinstance(tag, FelicaStandard):
        return

    station_code_lookup = StationCodeLookup()

    polling_result = tag.polling(SYSTEM_CODE)
    if len(polling_result) != 2:
        raise RuntimeError("Polling 応答が不正です。")
    tag.idm, tag.pmm = polling_result

    client = FelicaRemoteClient(resolve_server_url(), tag)
    try:
        auth_result = client.mutual_authentication(
            SYSTEM_CODE,
            list(AREA_NODE_IDS),
            list(SERVICE_NODE_IDS),
        )
    except FelicaRemoteClientError as exc:
        raise RuntimeError(f"Remote authentication failed: {exc}") from exc

    idi_hex = (auth_result.get("issue_id") or auth_result.get("idi") or "").upper()
    pmi_hex = (
        auth_result.get("issue_parameter") or auth_result.get("pmi") or ""
    ).upper()

    if not idi_hex:
        raise RuntimeError("Server response missing issue_id.")
    if not pmi_hex:
        raise RuntimeError("Server response missing issue_parameter.")

    try:
        idi_bytes = bytes.fromhex(idi_hex)
    except ValueError as exc:
        raise RuntimeError("Issue ID is not valid hex.") from exc

    print_section("カード識別")
    print_item("IDm", client.idm.hex().upper())
    print_item("PMm", client.pmm.hex().upper())
    print_item("IDi", idi_bytes_to_str(idi_bytes))
    print_item("PMi", pmi_hex)
    print()

    reader = RemoteCardReader(client)
    reporter = SuicaTagReporter(reader, station_code_lookup)
    reporter.print_issue_information(leading_newline=False)
    reporter.print_attribute_information()
    reporter.print_unknown_information()
    reporter.print_last_topup_information()
    reporter.print_transaction_history()
    # reporter.print_unknown_blocks()
    reporter.print_commuter_pass_information()
    reporter.print_gate_in_out_information()
    reporter.print_sf_gate_in_information()


def fix_ic_code_map():
    FelicaStandard.IC_CODE_MAP[0x31] = ("RC-S???", 1, 1)


def main() -> None:
    fix_ic_code_map()

    with nfc.ContactlessFrontend("usb") as clf:
        clf.connect(
            rdwr={
                "targets": ["212F", "424F"],  # FeliCa only
                "on-startup": on_startup,
                "on-connect": on_connect,
            }
        )


if __name__ == "__main__":
    main()
