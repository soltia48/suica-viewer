import { Channel, invoke } from "@tauri-apps/api/core";
import type { ComponentChildren } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import { History } from "./History";
import type {
  CardData,
  GateEntry,
  PaidTicketEntry,
  ReaderEvent,
  ReaderState,
  TransactionEntry,
} from "./types";

type Tab = "overview" | "cardinfo" | "history" | "gates" | "data";
type Theme = "light" | "dark" | "system";
type DisplayValue = string | number | null | undefined;

const tabs: Array<{ id: Tab; label: string }> = [
  { id: "overview", label: "概要" },
  { id: "cardinfo", label: "カード情報" },
  { id: "history", label: "取引履歴" },
  { id: "gates", label: "改札" },
  { id: "data", label: "データ" },
];

const yen = (value: number | null | undefined) =>
  typeof value === "number" ? `${value.toLocaleString("ja-JP")} 円` : "—";

const delta = (value: number | null | undefined) => {
  if (typeof value !== "number") return "—";
  return `${value > 0 ? "+" : ""}${value.toLocaleString("ja-JP")} 円`;
};

const dash = (value: DisplayValue) =>
  value === null || value === undefined || value === "" ? "—" : String(value);

const hhmm = (value: string) =>
  value.length >= 4 ? `${value.slice(0, 2)}:${value.slice(2, 4)}` : "—";

const hasCommuter = (card: CardData) =>
  Boolean(card.commuter.valid_from && card.commuter.valid_from !== "—");

function CardPanel({
  title,
  children,
}: {
  title: string;
  children: ComponentChildren;
}) {
  return (
    <div class="card">
      <h2>{title}</h2>
      <div class="body">{children}</div>
    </div>
  );
}

function EmptyCard({ title, message }: { title: string; message: string }) {
  return (
    <CardPanel title={title}>
      <div class="empty">
        <p>{message}</p>
        <p>リーダーにカードをかざすと、自動で表示されます。</p>
      </div>
    </CardPanel>
  );
}

function KeyValues({ rows }: { rows: Array<[string, DisplayValue]> }) {
  return (
    <dl class="grid">
      {rows.map(([label, value]) => (
        <div class="grid-row" key={label}>
          <dt>{label}</dt>
          <dd>{dash(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function Overview({
  card,
  readerState,
  onHistory,
}: {
  card: CardData | null;
  readerState: ReaderState;
  onHistory: () => void;
}) {
  if (!card) {
    const title =
      readerState === "reading"
        ? "カードを読み取っています"
        : readerState === "initializing"
          ? "リーダーに接続しています"
          : readerState === "error"
            ? "接続状態を確認してください"
            : "カードをかざしてください";
    return (
      <div class="welcome card">
        <svg
          class="reader-illustration"
          width="80"
          height="80"
          viewBox="0 0 80 80"
          fill="none"
          aria-hidden="true"
        >
          <rect
            x="12"
            y="37"
            width="56"
            height="31"
            rx="8"
            stroke="currentColor"
            stroke-width="2"
          />
          <rect
            x="23"
            y="11"
            width="34"
            height="45"
            rx="5"
            fill="var(--surface)"
            stroke="currentColor"
            stroke-width="2"
          />
          <path
            d="M34 26a10 10 0 0 1 0 16m5-19a15 15 0 0 1 0 22m-10-15a5 5 0 0 1 0 8"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
          />
          <path
            d="M34 62h12"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
          />
        </svg>
        <h2>{title}</h2>
        <p>
          {readerState === "reading"
            ? "読み取りが終わるまで、カードをリーダーに置いたままにしてください。"
            : readerState === "error"
              ? "上の案内に沿って、リーダーと通信環境を確認してください。"
              : "Suica などの交通系 IC カードの残高や利用履歴を確認できます。"}
        </p>
        <ol class="read-steps">
          <li>
            <span class="step-number" aria-hidden="true">
              1
            </span>
            <span>リーダーを PC に接続</span>
          </li>
          <li>
            <span class="step-number" aria-hidden="true">
              2
            </span>
            <span>カードをリーダーに置く</span>
          </li>
          <li>
            <span class="step-number" aria-hidden="true">
              3
            </span>
            <span>自動で読み取り・表示</span>
          </li>
        </ol>
        <p class="welcome-note">
          カードを離すと表示が消えます。必要な情報は「データ」から保存できます。
        </p>
      </div>
    );
  }

  return (
    <>
      <div class="overview-summary">
        <div class="hero">
          <h2 class="cap">カード残高</h2>
          <div class="amount">
            {card.attribute.balance.toLocaleString("ja-JP")}
            <span class="currency">円</span>
          </div>
          <div class="sub">
            {card.issue_primary.issuer_id || "交通系 IC カード"}
          </div>
          {card.issue_primary.collected && (
            <div class="flag">取り込み済み（無効カード）</div>
          )}
          <div class="hero-footer">
            <span>最終チャージ</span>
            <strong>{yen(card.last_topup.amount)}</strong>
          </div>
        </div>
        <div class="commuter-summary card">
          <h2>定期券</h2>
          <div class="body">
            {hasCommuter(card) ? (
              <>
                <div class="commuter-route">
                  <span>{dash(card.commuter.start_station)}</span>
                  <span class="route-connector" aria-hidden="true">
                    →
                  </span>
                  <span class="sr-only">から</span>
                  <span>{dash(card.commuter.end_station)}</span>
                </div>
                <p class="muted">有効期間</p>
                <p class="commuter-dates">
                  {card.commuter.valid_from} 〜 {card.commuter.valid_to}
                </p>
                <p class="muted commuter-issuer">{card.commuter.issuer_id}</p>
              </>
            ) : (
              <div class="commuter-empty">
                <p>定期券の登録はありません</p>
                <p class="muted">区間・有効期間の記録はありません。</p>
              </div>
            )}
          </div>
        </div>
      </div>

      <div class="card recent-card">
        <div class="card-heading">
          <h2>最近の取引</h2>
          <button class="ghost" type="button" onClick={onHistory}>
            取引履歴を見る <span aria-hidden="true">→</span>
          </button>
        </div>
        <div class="body">
          {card.transaction_history.length ? (
            <ul class="recent-list">
              {card.transaction_history.slice(0, 3).map((entry) => (
                <li key={entry.index}>
                  <div class="recent-date">
                    {entry.recorded_on}
                    {entry.transaction_time && (
                      <span>{entry.transaction_time}</span>
                    )}
                  </div>
                  <div class="recent-description">
                    <strong>{entry.transaction_type}</strong>
                    <span class="muted">
                      {entry.transaction_type_code === 0x46
                        ? entry.recorded_by
                        : entry.bus_company ||
                          [entry.entry_station, entry.exit_station]
                            .filter((station) => station && station !== "—")
                            .join(" → ") || entry.recorded_by}
                    </span>
                  </div>
                  <div
                    class={`recent-amount ${typeof entry.delta === "number" && entry.delta > 0 ? "amount-positive" : ""}`}
                  >
                    {delta(entry.delta)}
                    <span class="muted">残高 {yen(entry.balance)}</span>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p class="empty">このカードには取引履歴がありません。</p>
          )}
        </div>
      </div>

      <details class="card identity-details">
        <summary>カード識別・発行情報</summary>
        <div class="body cols">
          <KeyValues
            rows={[
              ["IDm", card.system.idm_hex],
              ["PMm", card.system.pmm_hex],
              ["IDi", card.system.idi_display],
              ["PMi", card.system.pmi],
              ["発行者", card.issue_primary.issuer_id],
            ]}
          />
          <KeyValues
            rows={[
              ["発行日", card.issue_primary.issued_at],
              ["有効期限", card.issue_primary.expires_at],
              ["発行駅", card.issue_primary.issued_station],
              [
                "取り込み済み",
                card.issue_primary.collected ? "はい（無効カード）" : "いいえ",
              ],
            ]}
          />
        </div>
      </details>
    </>
  );
}

function CardInfo({ card }: { card: CardData | null }) {
  if (!card) {
    return (
      <EmptyCard title="カード情報" message="カードが読み取られていません。" />
    );
  }

  const issue = card.issue_primary;
  const attribute = card.attribute;
  const topup = card.last_topup;
  const commuter = card.commuter;
  const use = (value: boolean) => (value ? "利用する" : "利用しない");
  const yesNo = (value: boolean) => (value ? "有" : "無");

  return (
    <div class="cols">
      <CardPanel title="発行情報">
        <KeyValues
          rows={[
            ["所有者名", issue.owner_name],
            ["生年月日", issue.owner_birthdate],
            ["電話番号(hex)", issue.owner_phone_hex],
            ["年齢コード", issue.owner_age_code],
            ["第二発行ID", issue.secondary_issue_id],
            ["発行者ID", issue.issuer_id],
            ["デポジット額", yen(issue.deposit)],
            ["発行機器", issue.issued_by],
            ["発行駅", issue.issued_station],
            ["発行日", issue.issued_at],
            ["有効期限", issue.expires_at],
            ["取り込み済み", issue.collected ? "はい（無効カード）" : "いいえ"],
          ]}
        />
      </CardPanel>
      <CardPanel title="カード属性">
        <KeyValues
          rows={[
            ["残高", yen(attribute.balance)],
            ["取引通番", attribute.transaction_number.toLocaleString("ja-JP")],
            ["音声案内サービス", use(attribute.voice_guidance)],
            ["定期有効期間外のSF利用", use(attribute.sf_outside_commuter)],
            ["タッチでGo！新幹線", use(attribute.touch_de_go)],
          ]}
        />
      </CardPanel>
      <CardPanel title="最終チャージ情報">
        <KeyValues
          rows={[
            ["チャージ機器", topup.equipment],
            ["チャージ駅", topup.station],
            ["チャージ金額", yen(topup.amount)],
          ]}
        />
      </CardPanel>
      <CardPanel title="定期券情報">
        {hasCommuter(card) ? (
          <KeyValues
            rows={[
              ["発行事業者", commuter.issuer_id],
              ["開始日", commuter.valid_from],
              ["終了日", commuter.valid_to],
              ["始点駅", commuter.start_station],
              ["終点駅", commuter.end_station],
              ["経由駅1", commuter.via1_station],
              ["経由駅2", commuter.via2_station],
              ["券番", commuter.pass_number],
              ["発売額", yen(commuter.sale_price)],
              ["購入時支払方法", commuter.purchase_pay_type],
              ["R通番", commuter.r_number],
              ["発行日", commuter.issued_at],
              ...(commuter.commuter_certificate_expiry &&
              commuter.commuter_certificate_expiry !== "—"
                ? ([
                    [
                      "通学証明書省略期限",
                      commuter.commuter_certificate_expiry,
                    ],
                  ] as Array<[string, string]>)
                : []),
            ]}
          />
        ) : (
          <div class="empty">定期券なし</div>
        )}
      </CardPanel>
      <CardPanel title="オートチャージ">
        <KeyValues
          rows={[
            ["契約", yesNo(card.auto_charge.contracted)],
            ["有効", yesNo(card.auto_charge.enabled)],
            ...(card.auto_charge.contracted
              ? ([
                  ["チャージ額", yen(card.auto_charge.charge_amount)],
                  ["しきい値", yen(card.auto_charge.threshold)],
                ] as Array<[string, string]>)
              : []),
          ]}
        />
      </CardPanel>
    </div>
  );
}

interface Column<Row> {
  label: string;
  numeric?: boolean;
  value: (row: Row) => DisplayValue;
}

function DataTable<Row>({
  columns,
  rows,
  label,
}: {
  columns: Array<Column<Row>>;
  rows: Row[];
  label: string;
}) {
  return (
    <>
      <p class="table-hint">表が収まらない場合は横にスクロールできます。</p>
      <div
        class="tablewrap"
        role="region"
        aria-label={`${label}の表（横にスクロールできます）`}
        tabIndex={0}
      >
        <table aria-label={label}>
          <thead>
            <tr>
              {columns.map((column) => (
                <th
                  scope="col"
                  class={column.numeric ? "num" : undefined}
                  key={column.label}
                >
                  {column.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={index}>
                {columns.map((column) => (
                  <td
                    class={column.numeric ? "num" : undefined}
                    key={column.label}
                  >
                    {dash(column.value(row))}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

const gateColumns: Array<Column<GateEntry>> = [
  {
    label: "日時",
    value: (entry) => `${dash(entry.date)} ${entry.time || ""}`.trim(),
  },
  { label: "入出場種別", value: (entry) => entry.gate_in_out_type },
  {
    label: "中間処理",
    value: (entry) => entry.intermediate_gate_instruction_type,
  },
  { label: "駅", value: (entry) => entry.station },
  { label: "装置番号", value: (entry) => entry.device_id_hex },
  { label: "金額", numeric: true, value: (entry) => yen(entry.amount) },
  {
    label: "定期運賃",
    numeric: true,
    value: (entry) => yen(entry.commuter_pass_fee),
  },
  { label: "定期駅", value: (entry) => entry.commuter_station },
];

const paidTicketColumns: Array<Column<PaidTicketEntry>> = [
  { label: "発駅", value: (entry) => entry.depart_station },
  { label: "着駅", value: (entry) => entry.arrive_station },
  { label: "有効期限", value: (entry) => entry.expires_at },
  { label: "金額", numeric: true, value: (entry) => yen(entry.amount) },
  { label: "発券時刻", value: (entry) => entry.issued_time },
  { label: "発券種別", value: (entry) => entry.issue_type_hex },
  { label: "装置番号", value: (entry) => entry.device_id_hex },
  { label: "改札実施駅", value: (entry) => entry.checked_station },
  { label: "改札実施時刻", value: (entry) => entry.checked_time },
];

function Gates({ card }: { card: CardData | null }) {
  if (!card)
    return <EmptyCard title="改札" message="カードが読み取られていません。" />;

  return (
    <>
      <CardPanel title="改札入出場履歴">
        {card.gate.length ? (
          <DataTable
            columns={gateColumns}
            rows={card.gate}
            label="改札入出場履歴"
          />
        ) : (
          <div class="empty">改札入出場記録なし</div>
        )}
      </CardPanel>
      {card.sf_gate.has_record ? (
        <CardPanel title="SF改札入場情報">
          <KeyValues
            rows={[
              ["入場駅", card.sf_gate.entry_station],
              ["中間改札入場駅", card.sf_gate.intermediate_entry_station],
              ["中間改札入場日付", card.sf_gate.intermediate_entry_date],
              ["中間改札入場時刻", hhmm(card.sf_gate.intermediate_entry_time)],
              ["中間改札出場駅", card.sf_gate.intermediate_exit_station],
              ["中間改札出場時刻", hhmm(card.sf_gate.intermediate_exit_time)],
            ]}
          />
        </CardPanel>
      ) : (
        <CardPanel title="SF改札入場情報">
          <p class="empty">このカードには入場記録がありません。</p>
        </CardPanel>
      )}
      <CardPanel title="料金発券・改札情報">
        {card.paid_ticket.length ? (
          <DataTable
            columns={paidTicketColumns}
            rows={card.paid_ticket}
            label="料金発券・改札情報"
          />
        ) : (
          <div class="empty">
            {card.paid_ticket_available
              ? "記録なし"
              : card.paid_ticket_reason || "記録なし"}
          </div>
        )}
      </CardPanel>
    </>
  );
}

const csvColumns: Array<[string, (entry: TransactionEntry) => DisplayValue]> = [
  ["日付", (entry) => entry.recorded_on],
  ["時刻", (entry) => entry.transaction_time],
  ["取引種別", (entry) => entry.transaction_type],
  ["支払種別", (entry) => entry.pay_type],
  ["改札処理", (entry) => entry.gate_instruction_type],
  ["入場駅", (entry) => entry.entry_station],
  ["出場駅", (entry) => entry.exit_station],
  ["差額", (entry) => entry.delta],
  ["残高", (entry) => entry.balance],
  ["機器", (entry) => entry.recorded_by],
  ["通番", (entry) => entry.transaction_number],
  ["バス事業者", (entry) => entry.bus_company],
  [
    "バス停コード",
    (entry) =>
      entry.bus_stop == null
        ? undefined
        : `0x${entry.bus_stop.toString(16).toUpperCase().padStart(4, "0")}`,
  ],
];

const csvCell = (value: DisplayValue) => {
  const string = String(value ?? "");
  return /[",\n]/.test(string) ? `"${string.replaceAll('"', '""')}"` : string;
};

function download(name: string, text: string, type: string) {
  const body = type.includes("csv") ? `\uFEFF${text}` : text;
  const url = URL.createObjectURL(new Blob([body], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function DataView({ card }: { card: CardData | null }) {
  const [feedback, setFeedback] = useState<{
    message: string;
    error?: boolean;
  } | null>(null);
  const feedbackFrame = useRef<number | null>(null);

  useEffect(() => setFeedback(null), [card]);
  useEffect(
    () => () => {
      if (feedbackFrame.current !== null)
        cancelAnimationFrame(feedbackFrame.current);
    },
    [],
  );

  const announceFeedback = (next: { message: string; error?: boolean }) => {
    if (feedbackFrame.current !== null)
      cancelAnimationFrame(feedbackFrame.current);
    setFeedback(null);
    // Commit an empty region first so repeated saves can be announced again.
    feedbackFrame.current = requestAnimationFrame(() => {
      feedbackFrame.current = null;
      setFeedback(next);
    });
  };

  const copyJson = async () => {
    if (!card) return;
    setFeedback(null);
    try {
      await navigator.clipboard.writeText(JSON.stringify(card, null, 2));
      announceFeedback({ message: "JSON をコピーしました。" });
    } catch {
      announceFeedback({
        message:
          "JSON をコピーできませんでした。「JSON を保存」でファイルに保存できます。",
        error: true,
      });
    }
  };

  const exportData = (format: "json" | "csv") => {
    if (!card) return;
    try {
      if (format === "json") {
        download(
          "suica_card.json",
          JSON.stringify(card, null, 2),
          "application/json",
        );
      } else {
        const lines = [csvColumns.map(([label]) => label).join(",")];
        for (const entry of card.transaction_history) {
          lines.push(
            csvColumns.map(([, value]) => csvCell(value(entry))).join(","),
          );
        }
        download("suica_history.csv", lines.join("\r\n"), "text/csv");
      }
      announceFeedback({
        message: `${format === "json" ? "JSON" : "CSV"} の保存を開始しました。`,
      });
    } catch {
      announceFeedback({
        message: "保存を開始できませんでした。もう一度保存を実行してください。",
        error: true,
      });
    }
  };

  return (
    <CardPanel title="データを書き出す">
      <p class="section-intro">
        {card
          ? "カード情報は JSON、取引履歴は CSV で保存できます。"
          : "カードを読み取ると、カード情報や取引履歴を保存できます。"}
      </p>
      <div class="toolbar">
        <button class="ghost" type="button" disabled={!card} onClick={copyJson}>
          JSON をコピー
        </button>
        <button
          class="ghost"
          type="button"
          disabled={!card}
          onClick={() => exportData("json")}
        >
          JSON を保存
        </button>
        <button
          class="ghost"
          type="button"
          disabled={!card}
          onClick={() => exportData("csv")}
        >
          履歴を CSV で保存
        </button>
      </div>
      <p
        class={`export-feedback ${feedback?.error ? "error" : ""}`}
        role="status"
        aria-atomic="true"
      >
        {feedback?.message}
      </p>
      {card && (
        <pre
          class="json"
          tabIndex={0}
          role="region"
          aria-label="カード情報 JSON"
        >
          {JSON.stringify(card, null, 2)}
        </pre>
      )}
    </CardPanel>
  );
}

function initialTheme(): Theme {
  try {
    const stored = localStorage.getItem("suica-theme");
    if (stored === "light" || stored === "dark" || stored === "system")
      return stored;
  } catch {
    // Theme selection remains available if storage is unavailable.
  }
  return "system";
}

export function App() {
  const [activeTab, setActiveTab] = useState<Tab>("overview");
  const [card, setCard] = useState<CardData | null>(null);
  const [readAt, setReadAt] = useState<string | null>(null);
  const [readerState, setReaderState] = useState<ReaderState>("initializing");
  const [statusMessage, setStatusMessage] =
    useState("NFC リーダーに接続しています…");
  const [progress, setProgress] = useState(0);
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [systemIsDark, setSystemIsDark] = useState(
    () => matchMedia("(prefers-color-scheme: dark)").matches,
  );

  useEffect(() => {
    const preference = matchMedia("(prefers-color-scheme: dark)");
    const updatePreference = () => setSystemIsDark(preference.matches);
    updatePreference();
    preference.addEventListener("change", updatePreference);
    return () => preference.removeEventListener("change", updatePreference);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme =
      theme === "system" ? (systemIsDark ? "dark" : "light") : theme;
    try {
      localStorage.setItem("suica-theme", theme);
    } catch {
      // Apply the selection for this session even when it cannot be persisted.
    }
  }, [theme, systemIsDark]);

  useEffect(() => {
    const channel = new Channel<ReaderEvent>();
    channel.onmessage = (event) => {
      switch (event.type) {
        case "status":
          setReaderState(event.state);
          setStatusMessage(event.message);
          if (event.state !== "reading") setProgress(0);
          break;
        case "progress":
          setProgress(
            Number.isFinite(event.value)
              ? Math.max(0, Math.min(100, event.value))
              : 0,
          );
          break;
        case "card":
          setCard(event.data);
          setReadAt(event.read_at);
          setProgress(100);
          break;
        case "error":
          setReaderState("error");
          setStatusMessage(event.message);
          setProgress(0);
          break;
        case "removed":
          setCard(null);
          setReadAt(null);
          setProgress(0);
          break;
      }
    };

    invoke("reader_events", { onEvent: channel }).catch((error: unknown) => {
      setReaderState("error");
      setStatusMessage(`リーダーとの接続に失敗しました: ${String(error)}`);
    });

    return () => {
      channel.onmessage = () => {};
    };
  }, []);

  const hasReaderError =
    readerState === "error" ||
    (readerState === "waiting" && /エラー|失敗|不正/.test(statusMessage));
  const isReading = readerState === "reading";
  const readerLabel = hasReaderError
    ? readerState === "error"
      ? "読み取りを開始できません"
      : "カードを読み取れませんでした"
    : statusMessage;
  const recoveryMessage =
    readerState !== "error"
      ? /サーバ|通信|ネットワーク|HTTP|request|connect/i.test(statusMessage)
        ? "インターネット接続と認証サーバの状態を確認し、カードを置き直してください。"
        : "カードをいったん離し、リーダーの中央に置き直してください。"
      : statusMessage.includes("認証サーバ")
        ? "認証サーバの設定を確認し、アプリを起動し直してください。"
        : "リーダーの USB 接続と下のエラー内容を確認し、アプリを起動し直してください。";

  const handleTabKeyDown = (event: KeyboardEvent, currentTab: Tab) => {
    const index = tabs.findIndex((tab) => tab.id === currentTab);
    let nextIndex: number;
    switch (event.key) {
      case "ArrowRight":
        nextIndex = (index + 1) % tabs.length;
        break;
      case "ArrowLeft":
        nextIndex = (index - 1 + tabs.length) % tabs.length;
        break;
      case "Home":
        nextIndex = 0;
        break;
      case "End":
        nextIndex = tabs.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    const nextTab = tabs[nextIndex].id;
    setActiveTab(nextTab);
    document.getElementById(`tab-${nextTab}`)?.focus();
  };

  return (
    <main class="wrap">
      <a class="skip-link" href={`#panel-${activeTab}`}>
        カード情報へ移動
      </a>
      <header class="top">
        <div class="brand">
          <h1 translate={false}>Suica Viewer</h1>
          <p class="app-caption">交通系 IC カードの残高・利用履歴</p>
        </div>
        <label class="theme-control">
          <span>表示</span>
          <select
            value={theme}
            onChange={(event) => setTheme(event.currentTarget.value as Theme)}
          >
            <option value="system">システム</option>
            <option value="light">ライト</option>
            <option value="dark">ダーク</option>
          </select>
        </label>
      </header>

      <div class="reader-bar">
        <span class="status" role="status" aria-atomic="true">
          <span
            class={`dot ${hasReaderError ? "error" : readerState}`}
            aria-hidden="true"
          />
          <span>{readerLabel}</span>
        </span>
        {readAt && <span class="meta">読取日時: {readAt}</span>}
      </div>

      <div role="alert" aria-atomic="true">
        {hasReaderError && (
          <div class="reader-notice error">
            <p class="reader-notice-title">{recoveryMessage}</p>
            <p class="reader-notice-detail">{statusMessage}</p>
          </div>
        )}
      </div>
      {isReading && (
        <div class="reader-notice reading">
          <p class="reader-notice-title">
            読み取りが終わるまで、カードを動かさずにお待ちください。
          </p>
          <progress
            class="progress"
            max={100}
            value={progress}
            aria-label="カード情報の読み取り"
          />
        </div>
      )}

      <div class="tabs" role="tablist" aria-label="カード情報">
        {tabs.map((tab) => (
          <button
            type="button"
            role="tab"
            id={`tab-${tab.id}`}
            aria-controls={`panel-${tab.id}`}
            aria-selected={activeTab === tab.id}
            tabIndex={activeTab === tab.id ? 0 : -1}
            onClick={() => setActiveTab(tab.id)}
            onKeyDown={(event) => handleTabKeyDown(event, tab.id)}
            key={tab.id}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {tabs.map((tab) => (
        <section
          class="tab-panel"
          role="tabpanel"
          id={`panel-${tab.id}`}
          aria-labelledby={`tab-${tab.id}`}
          tabIndex={0}
          hidden={activeTab !== tab.id}
          aria-busy={isReading}
          key={tab.id}
        >
          {tab.id === "overview" && (
            <Overview
              card={card}
              readerState={hasReaderError ? "error" : readerState}
              onHistory={() => {
                setActiveTab("history");
                requestAnimationFrame(() =>
                  document.getElementById("panel-history")?.focus(),
                );
              }}
            />
          )}
          {tab.id === "cardinfo" && <CardInfo card={card} />}
          {tab.id === "history" && (
            <History key={card?.system.idm_hex ?? "no-card"} card={card} />
          )}
          {tab.id === "gates" && <Gates card={card} />}
          {tab.id === "data" && (
            <DataView key={card?.system.idm_hex ?? "no-card"} card={card} />
          )}
        </section>
      ))}
    </main>
  );
}
