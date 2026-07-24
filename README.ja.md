# Suica Viewer

Suica Viewer は、FeliCa ベースの交通系 IC カードから詳細な情報を取得し、表示・保存するためのツールです。暗号領域の読み出しにはリモート認証サーバーを利用し、コンソール向け CLI とローカル Web GUI の 2 つのエントリーポイントを提供します。

リーダー制御と FeliCa プロトコルの実装には [felica-rs](https://github.com/soltia48/felica-rs) を使用しています。

## 主な機能
- リモートサーバー経由での相互認証と暗号領域読み出し
- CLI 版: 発行情報・残高・履歴・定期券情報などをテキストで整形出力
- Web GUI 版: 概要／カード情報／取引履歴／改札／データの各タブを備えたビジュアルビューア、履歴フィルタ、JSON のコピー・保存機能
- `station_codes.csv` に基づく会社名・路線名・駅名の解決（実行ファイルに同梱）
- `AUTH_SERVER_URL` 環境変数での認証サーバーの切り替え（既定: `https://felica-auth.nyaa.ws`）

## 必要環境
- [Rust](https://www.rust-lang.org/) 1.85 以降（ソースからビルドする場合。edition 2024 を使用）
- felica-rs が対応している FeliCa リーダー／ライター

| デバイス | VID:PID |
| --- | --- |
| Sony RC-S380 (Port-100) | 054C:06C1, 054C:06C3 |
| Sony RC-S300 (Port-400) | 054C:0DC8, 054C:0DC9, 054C:0D8F |
| Sony RC-S320 | 054C:01BB |
| Sony RC-S330 / RC-S360 / RC-S370 (RC-S956) | 054C:02E1, 054C:0193 |

- リーダーに libusb 互換ドライバーが割り当てられていること（[リーダーのドライバー設定](#リーダーのドライバー設定)を参照）
- インターネット接続（リモート認証サーバーとの通信に使用）

## インストール

### ビルド済み実行ファイル
リリースごとに `suica-viewer` と `suica-viewer-web` の単体実行ファイルを配布しています。駅コードデータと Web UI は実行ファイルに埋め込まれているため、追加ファイルは不要です。[Releases](../../releases) から環境に合うファイルを、検証用の `SHA256SUMS.txt` とあわせてダウンロードしてください。

| 環境 | ファイル名の末尾 |
| --- | --- |
| Linux (x86_64) | `-linux-x86_64` |
| Windows (x86_64) | `-windows-x86_64.exe` |
| macOS (Apple Silicon) | `-macos-arm64` |
| macOS (Intel) | `-macos-x86_64` |

macOS 版は署名していないため、初回起動時に Gatekeeper がブロックします。「システム設定 → プライバシーとセキュリティ」から実行を許可してください。

実行ファイルを使う場合もリーダーのドライバー設定は必要です。[リーダーのドライバー設定](#リーダーのドライバー設定)を参照してください。

### ソースから

```bash
cargo build --release
# 成果物: target/release/suica-viewer, target/release/suica-viewer-web
```

libusb 本体は `rusb` がソースからビルドするため、別途インストールする必要はありません。Linux では列挙のために libudev を参照するので、`libudev-dev`（Debian/Ubuntu）を入れておいてください。

## リーダーのドライバー設定
felica-rs は libusb 経由でリーダーと通信します。libusb が USB デバイスを掴めるドライバーが割り当てられている必要があります。

**Windows.** 既定では Windows がリーダーに独自のドライバーを割り当てており、libusb から開けません。[Zadig](https://zadig.akeo.ie/) でリーダーのドライバーを **WinUSB** に置き換えてください。置き換えると、デバイスマネージャーで元のドライバーに戻すまで、メーカー純正ソフト（Sony の NFC ポートソフトウェアなど）からはリーダーを利用できなくなります。

**Linux.** ユーザーがデバイスへアクセスできるようにします。

```bash
# Sony RC-S380 (0x054c:0x06c1, 0x054c:0x06c3) 向けの udev ルール例
echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="054c", ATTRS{idProduct}=="06c3", GROUP="plugdev", MODE="0664"' \
  | sudo tee /etc/udev/rules.d/60-suica-viewer.rules
sudo udevadm control --reload-rules
```

ルールを追加しない場合は root 権限での実行が必要です。

**macOS.** 追加の設定は不要です。

## 使い方 (CLI)
1. 対応する FeliCa リーダーを PC に接続
2. 必要であれば `AUTH_SERVER_URL` を設定し、リモートサーバーを指定
3. 下記コマンドでカードをかざすと、詳細情報がコンソールに出力

```bash
suica-viewer
# 例:
# AUTH_SERVER_URL=https://example.com suica-viewer
```

出力は残高サマリを先頭に、色付き・表形式で整形されます（TTY 以外や `NO_COLOR` 環境変数では自動的に無彩色）。

オプション
- `--json` : 表形式ではなく JSON を出力（スクリプト連携用）
- `-v`, `--verbose` : 装置番号・生コードなどの詳細フィールドも表示
- `--no-color` : ANSI カラーを無効化
- `--server URL` : 認証サーバーの URL を指定（`AUTH_SERVER_URL` より優先）

主な出力項目
- システム発行情報 (IDi, PMi)
- 発行情報（発行者／発行駅／有効期限など）
- 属性情報（カード種別・残高・取引通番）
- 取引履歴（入出場改札／物販／チャージなどを解析。1 取引ごとの増減額も表示）
- 定期券情報、改札入出場情報、SF 改札入場情報
- 料金発券・改札情報（サービス `0x1848`）— カードが搭載する場合のみ存在確認して自動取得。非搭載のカードや、認証サーバに該当鍵が無い場合は、他の情報に影響を与えずスキップ

## 使い方 (Web GUI)
ブラウザから直接 USB リーダーや相互認証の中継はできないため、`suica-viewer-web` はリーダーを保持するローカルサーバを起動し、Server-Sent Events でカード情報をブラウザへ配信します。

```bash
suica-viewer-web
# 既定で http://127.0.0.1:8765/ をブラウザで開きます
```

- カードを自動検出し、リロードなしでページをライブ更新します。残高ヒーローカード、タブ構成、差額付きの並び替え可能な取引履歴、改札テーブル、JSON/CSV 出力、ライト／ダークテーマに対応。
- カードをリーダーから離すとページの表示もクリアされ、次のカードを待ちます。
- 既定では `127.0.0.1` にのみバインドします。`--host 0.0.0.0` を指定すると LAN に公開されますが、カード情報がネットワークに流れる点に注意してください。

オプション

| フラグ | 説明 |
| --- | --- |
| `--host` / `--port` | バインド先（既定 `127.0.0.1:8765`） |
| `--server URL` | 認証サーバの URL（`AUTH_SERVER_URL` より優先） |
| `--no-browser` | 起動時にブラウザを自動で開かない |
| `--demo` | リーダーなしで疑似カードを使い UI をプレビュー |

## 認証サーバーの設定
- 既定値: `https://felica-auth.nyaa.ws`
- 環境変数 `AUTH_SERVER_URL` にベース URL を指定すると切り替え可能です（末尾スラッシュは不要）。
- サーバーは以下のエンドポイントを提供する必要があります。
  - `POST /mutual-authentication`
  - `POST /encryption-exchange`
- 相互認証の途中ステップではカードとのコマンド／レスポンスを往復させる想定です。状況によっては個人情報やカード識別子が送信されるため、信頼できる環境のみに接続してください。

## 駅コードデータ
- `assets/station_codes.csv` に JR 東日本などの駅コードが格納されており、線区コードと駅順コードから会社名・路線名・駅名を解決します。
- このファイルはビルド時に実行ファイルへ埋め込まれます。差し替える場合は CSV を編集して再ビルドしてください。

## トラブルシューティング
- Windows で `Operation not supported or unimplemented on this platform`: libusb はリーダーを認識していますが、libusb 互換ドライバーが割り当てられていないため開けません。[リーダーのドライバー設定](#リーダーのドライバー設定)のとおり Zadig で WinUSB ドライバーを導入してください。管理者権限で実行しても解決しません。
- Linux で `Access denied (insufficient permissions)`: USB デバイスへのアクセス権限がありません。上記の udev ルールを追加するか、root 権限で実行してください。
- `NFC リーダーを初期化できません` / `reader not found` と表示される場合: リーダーが接続されていないか、対応表にない VID/PID です。
- `サーバ通信エラー` が続く場合: 認証サーバー URL の設定やネットワーク接続を確認してください。必要に応じて `AUTH_SERVER_URL` を変更します。

`RUST_LOG=debug` を設定すると、カードとやり取りしたフレームを含む詳細ログが出力されます。

## 開発向けメモ
- 整形・静的解析・テスト: `cargo fmt --all` / `cargo clippy --all-targets` / `cargo test`
- リーダーなしで Web UI を確認する場合は `cargo run --bin suica-viewer-web -- --demo`
- `v*` タグを push すると [`.github/workflows/release.yml`](.github/workflows/release.yml) が全プラットフォームのビルドを行い、実行ファイルを GitHub Release に添付します。

## 開発者

- KIRISHIKI Yudai

## ライセンス

[MIT](https://opensource.org/licenses/MIT)

Copyright (c) 2025 KIRISHIKI Yudai
