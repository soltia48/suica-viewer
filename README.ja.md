# Suica Viewer

Suica Viewer は、FeliCa ベースの交通系 IC カードから詳細な情報を取得し、表示・保存するためのツールです。暗号領域の読み出しにはリモート認証サーバーを利用し、Tauri デスクトップアプリとコンソール向け CLI を提供します。

リーダー制御と FeliCa プロトコルの実装には [felica](https://github.com/soltia48/felica-rs) を使用しています。

## 主な機能
- リモートサーバー経由での相互認証と暗号領域読み出し
- デスクトップアプリ: Preact 製の概要／カード情報／取引履歴／改札／データ画面、履歴フィルタ、JSON・CSV 出力
- CLI 版: 発行情報・残高・履歴・定期券情報などをテキストで整形出力
- `station_codes.csv` に基づく会社名・路線名・駅名の解決（実行ファイルに同梱）
- `AUTH_SERVER_URL` 環境変数での認証サーバーの切り替え（既定: `https://felica-auth.nyaa.ws`）

## 必要環境
- [Rust](https://www.rust-lang.org/) 1.88 以降（ソースからビルドする場合。edition 2024 を使用）
- [Node.js](https://nodejs.org/) 20.19 以降（または 22.12 以降）と npm（Preact フロントエンドのビルドに使用）
- felica が対応している FeliCa リーダー／ライター

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
リリースごとにデスクトップアプリ `suica-viewer` とコンソール版 `suica-viewer-cli` を配布しています。駅コードデータと Preact UI は実行ファイルに埋め込まれているため、追加ファイルは不要です。[Releases](../../releases) から環境に合うファイルを、検証用の `SHA256SUMS.txt` とあわせてダウンロードしてください。

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
npm ci --prefix ui
npm exec --prefix ui -- tauri build --no-bundle
cargo build --release --locked --bin suica-viewer-cli
# 成果物: target/release/suica-viewer, target/release/suica-viewer-cli
```

libusb 本体は `rusb` がソースからビルドするため、別途インストールする必要はありません。Linux では [Tauri のシステム依存パッケージ](https://v2.tauri.app/start/prerequisites/#linux)に加え、リーダー列挙用の `libudev-dev` が必要です。

## リーダーのドライバー設定
felica は libusb 経由でリーダーと通信します。libusb が USB デバイスを掴めるドライバーが割り当てられている必要があります。

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
suica-viewer-cli
# 例:
# AUTH_SERVER_URL=https://example.com suica-viewer-cli
```

出力は残高サマリを先頭に、色付き・表形式で整形されます（TTY 以外や `NO_COLOR` 環境変数では自動的に無彩色）。

オプション
- `--json` : 表形式ではなく JSON を出力（スクリプト連携用）
- `-v`, `--verbose` : 装置番号・生コードなどの詳細フィールドも表示
- `--no-color` : ANSI カラーを無効化
- `--server URL` : 認証サーバーの URL を指定（`AUTH_SERVER_URL` より優先）

主な出力項目
- システム発行情報 (IDi, PMi)
- 発行情報（発行者／発行駅／有効期限／取り込み済み（無効）フラグなど）
- 属性情報（カード種別・残高・取引通番）
- 取引履歴（入出場改札／物販／チャージなどを解析。1 取引ごとの増減額も表示）
- 定期券情報、改札入出場情報、SF 改札入場情報
- 料金発券・改札情報（サービス `0x184B`）— カードが搭載する場合のみ存在確認して自動取得。非搭載のカードや、認証サーバに該当鍵が無い場合は、他の情報に影響を与えずスキップ

## 使い方 (デスクトップアプリ)
Tauri の Rust プロセスが USB リーダーを保持し、カード情報をローカル IPC Channel で組み込みの Preact UI へ配信します。HTTP サーバーは起動せず、カード情報をネットワークへ公開しません。

```bash
suica-viewer
```

- カードを自動検出し、リロードなしでページをライブ更新します。残高ヒーローカード、タブ構成、差額付きの並び替え可能な取引履歴、改札テーブル、JSON/CSV 出力、ライト／ダークテーマに対応。
- カードをリーダーから離すとページの表示もクリアされ、次のカードを待ちます。
- 専用のネイティブウィンドウを開き、カード読み取り処理は UI スレッドの外で実行します。

オプション

| フラグ | 説明 |
| --- | --- |
| `--server URL` | 認証サーバの URL（`AUTH_SERVER_URL` より優先） |
| `--demo` | リーダーなしで疑似カードを使い UI をプレビュー |

## 認証サーバーの設定
- 既定値: `https://felica-auth.nyaa.ws`
- 環境変数 `AUTH_SERVER_URL` にベース URL を指定すると切り替え可能です（末尾スラッシュは不要）。
- サーバーは `POST /mutual-authentication` を提供する必要があります。

### 通信内容
サーバーが関与するのは**相互認証だけ**です。認証中はサーバーが組み立てたコマンドフレームをカードへ中継し、カードの応答を返します。この過程で IDm・PMm とカードの認証応答がサーバーへ送信されます。

認証が成立すると、サーバーは一時的なセッション情報（DES セッション鍵・トランザクション ID・トランザクション通番）を返してセッションを破棄します。以降の暗号化 Read は**このプロセスがカードに対して直接**実行するため、**残高・履歴・氏名などのカードデータがサーバーを通ることはありません**。長期鍵の側もサーバーから出ません。

それでもカード識別子は送信されるため、信頼できるサーバーのみに接続してください。

### 認証するノード
ビューアは読み取りしか行わないため、同じデータを公開している read/write コードではなく、各サービスの**読み取り専用コード**を認証します。受け取ったセッション鍵ではカードを書き換えられず、`--read-only-nodes` で運用している認証サーバーでもそのまま認証できます。

| サービス | データ | 鍵 |
| --- | --- | --- |
| `0x004A` | 発行情報 | 要 |
| `0x0816` | その他（用途未確定） | 要 |
| `0x08CA` | 最終チャージ情報 | 要 |
| `0x104A` | 定期情報 | 要 |
| `0x008B` | 属性情報・残高 | 不要 |
| `0x090F` | 取引履歴 | 不要 |
| `0x108F` | 改札入出場情報 | 不要 |
| `0x10CB` | SF改札入場情報 | 不要 |
| `0x184B` | 料金発券情報（搭載時のみ） | 不要 |

FeliCa は鍵が必要なノードを鍵不要ノードより先に並べることを要求するため、この順序になっています。認証サーバー側は read/write コードだけでなく、これら読み取り専用コードの鍵を保持している必要があります。

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
- 初回に `npm ci --prefix ui` で UI の依存関係をインストールします。
- `npm exec --prefix ui -- tauri dev -- -- --demo` で、リーダーなしのデモモードを起動できます。
- フロントエンドの確認は `npm --prefix ui run build`、Rust の整形・静的解析・テストは `cargo fmt --all` / `cargo clippy --workspace --all-targets` / `cargo test --workspace` です。
- `v*` タグを push すると [`.github/workflows/release.yml`](.github/workflows/release.yml) が全プラットフォームのビルドを行い、デスクトップアプリと CLI を GitHub Release に添付します。

## 開発者

- KIRISHIKI Yudai

## ライセンス

[MIT](https://opensource.org/licenses/MIT)

Copyright (c) 2025 KIRISHIKI Yudai
