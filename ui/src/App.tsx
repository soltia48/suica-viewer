import { Channel, invoke } from "@tauri-apps/api/core";
import type { ComponentChildren } from "preact";
import { useEffect, useMemo, useState } from "preact/hooks";
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

function CardPanel({ title, children }: { title: string; children: ComponentChildren }) {
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
      <div class="empty">{message}</div>
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

function Overview({ card }: { card: CardData | null }) {
  return (
    <>
      <div class="hero">
        <div class="cap">残高</div>
        <div class="amount">{card ? yen(card.attribute.balance) : "—"}</div>
        <div class="sub">
          {card
            ? card.issue_primary.issuer_id || "カード読取済み"
            : "カードをかざしてください"}
        </div>
        {card?.issue_primary.collected && (
          <div class="flag">取り込み済み（無効カード）</div>
        )}
      </div>

      {!card ? (
        <EmptyCard title="カード識別" message="カードが読み取られていません。" />
      ) : (
        <div class="cols">
          <CardPanel title="カード識別">
            <KeyValues
              rows={[
                ["IDm", card.system.idm_hex],
                ["PMm", card.system.pmm_hex],
                ["IDi", card.system.idi_display],
                ["PMi", card.system.pmi],
                ["発行者", card.issue_primary.issuer_id],
              ]}
            />
          </CardPanel>
          <CardPanel title="利用サマリ">
            <KeyValues
              rows={[
                ["残高", yen(card.attribute.balance)],
                ["最終チャージ金額", yen(card.last_topup.amount)],
                ["取引通番", card.attribute.transaction_number.toLocaleString("ja-JP")],
              ]}
            />
          </CardPanel>
          <CardPanel title="発行・有効情報">
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
          </CardPanel>
          <CardPanel title="定期券ハイライト">
            <KeyValues
              rows={
                hasCommuter(card)
                  ? [
                      [
                        "区間",
                        `${card.commuter.start_station} → ${card.commuter.end_station}`,
                      ],
                      [
                        "有効期間",
                        `${card.commuter.valid_from} 〜 ${card.commuter.valid_to}`,
                      ],
                    ]
                  : [
                      ["区間", "—"],
                      ["状態", "定期券なし"],
                    ]
              }
            />
          </CardPanel>
        </div>
      )}
    </>
  );
}

function CardInfo({ card }: { card: CardData | null }) {
  if (!card) {
    return <EmptyCard title="カード情報" message="カードが読み取られていません。" />;
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
                    ["通学証明書省略期限", commuter.commuter_certificate_expiry],
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

interface HistoryColumn {
  key: string;
  label: string;
  numeric?: boolean;
  value: (entry: TransactionEntry) => DisplayValue;
  sortValue?: (entry: TransactionEntry) => string | number;
}

const historyColumns: HistoryColumn[] = [
  {
    key: "when",
    label: "日時",
    value: (entry) => `${entry.recorded_on} ${entry.transaction_time || ""}`.trim(),
  },
  { key: "transaction_type", label: "取引種別", value: (entry) => entry.transaction_type },
  { key: "pay_type", label: "支払種別", value: (entry) => entry.pay_type },
  {
    key: "gate_instruction_type",
    label: "改札処理",
    value: (entry) => entry.gate_instruction_type,
  },
  {
    key: "entry_station",
    label: "入場駅",
    value: (entry) => (entry.transaction_type_code === 0x46 ? "—" : entry.entry_station),
  },
  {
    key: "exit_station",
    label: "出場駅",
    value: (entry) => (entry.transaction_type_code === 0x46 ? "—" : entry.exit_station),
  },
  {
    key: "delta",
    label: "差額",
    numeric: true,
    value: (entry) => delta(entry.delta),
    sortValue: (entry) => entry.delta ?? Number.NEGATIVE_INFINITY,
  },
  {
    key: "balance",
    label: "残高",
    numeric: true,
    value: (entry) => yen(entry.balance),
    sortValue: (entry) => entry.balance,
  },
  { key: "recorded_by", label: "機器", value: (entry) => entry.recorded_by },
  {
    key: "transaction_number",
    label: "通番",
    numeric: true,
    value: (entry) => entry.transaction_number.toLocaleString("ja-JP"),
    sortValue: (entry) => entry.transaction_number,
  },
];

function History({ card }: { card: CardData | null }) {
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState<{ key: string | null; direction: 1 | -1 }>({
    key: null,
    direction: 1,
  });

  const rows = useMemo(() => {
    if (!card) return [];
    const query = filter.trim().toLocaleLowerCase("ja");
    const filtered = query
      ? card.transaction_history.filter((entry) =>
          historyColumns.some((column) =>
            dash(column.value(entry)).toLocaleLowerCase("ja").includes(query),
          ),
        )
      : card.transaction_history.slice();

    const column = historyColumns.find(({ key }) => key === sort.key);
    if (column) {
      filtered.sort((left, right) => {
        const a = column.sortValue?.(left) ?? dash(column.value(left));
        const b = column.sortValue?.(right) ?? dash(column.value(right));
        const comparison =
          typeof a === "number" && typeof b === "number"
            ? a - b
            : String(a).localeCompare(String(b), "ja");
        return comparison * sort.direction;
      });
    }
    return filtered;
  }, [card, filter, sort]);

  const sortBy = (key: string) => {
    setSort((current) =>
      current.key === key
        ? { key, direction: current.direction === 1 ? -1 : 1 }
        : { key, direction: 1 },
    );
  };

  return (
    <>
      <div class="toolbar">
        <input
          type="search"
          aria-label="取引履歴を検索"
          placeholder="フィルター (全文検索)…"
          value={filter}
          onInput={(event) => setFilter(event.currentTarget.value)}
        />
        <button class="ghost" type="button" onClick={() => setFilter("")}>
          クリア
        </button>
      </div>
      {!card ? (
        <div class="empty">カードが読み取られていません。</div>
      ) : (
        <>
          <div class="tablewrap">
            <table>
              <thead>
                <tr>
                  {historyColumns.map((column) => (
                    <th
                      class={column.numeric ? "num" : undefined}
                      key={column.key}
                      aria-sort={
                        sort.key !== column.key
                          ? "none"
                          : sort.direction === 1
                            ? "ascending"
                            : "descending"
                      }
                    >
                      <button type="button" onClick={() => sortBy(column.key)}>
                        {column.label}
                        <span class="arrow">
                          {sort.key === column.key ? (sort.direction === 1 ? "▲" : "▼") : ""}
                        </span>
                      </button>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((entry) => (
                  <tr class={typeof entry.delta === "number" && entry.delta > 0 ? "charge" : ""} key={entry.index}>
                    {historyColumns.map((column) => (
                      <td class={column.numeric ? "num" : undefined} key={column.key}>
                        {dash(column.value(entry))}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {rows.length === 0 && (
            <div class="empty">{filter ? "該当する取引がありません。" : "取引履歴なし"}</div>
          )}
        </>
      )}
    </>
  );
}

interface Column<Row> {
  label: string;
  numeric?: boolean;
  value: (row: Row) => DisplayValue;
}

function DataTable<Row>({ columns, rows }: { columns: Array<Column<Row>>; rows: Row[] }) {
  return (
    <div class="tablewrap">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th class={column.numeric ? "num" : undefined} key={column.label}>
                {column.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>
              {columns.map((column) => (
                <td class={column.numeric ? "num" : undefined} key={column.label}>
                  {dash(column.value(row))}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const gateColumns: Array<Column<GateEntry>> = [
  { label: "日時", value: (entry) => `${dash(entry.date)} ${entry.time || ""}`.trim() },
  { label: "入出場種別", value: (entry) => entry.gate_in_out_type },
  { label: "中間処理", value: (entry) => entry.intermediate_gate_instruction_type },
  { label: "駅", value: (entry) => entry.station },
  { label: "装置番号", value: (entry) => entry.device_id_hex },
  { label: "金額", numeric: true, value: (entry) => yen(entry.amount) },
  { label: "定期運賃", numeric: true, value: (entry) => yen(entry.commuter_pass_fee) },
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
  if (!card) return <EmptyCard title="改札" message="カードが読み取られていません。" />;

  return (
    <>
      <CardPanel title="改札入出場履歴">
        {card.gate.length ? (
          <DataTable columns={gateColumns} rows={card.gate} />
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
        <EmptyCard title="SF改札入場情報" message="記録なし" />
      )}
      <CardPanel title="料金発券・改札情報">
        {card.paid_ticket.length ? (
          <DataTable columns={paidTicketColumns} rows={card.paid_ticket} />
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

function DataView({
  card,
  setStatus,
}: {
  card: CardData | null;
  setStatus: (state: ReaderState, message: string) => void;
}) {
  const copyJson = async () => {
    if (!card) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(card, null, 2));
      setStatus("done", "JSON をコピーしました。");
    } catch {
      setStatus("error", "コピーに失敗しました。");
    }
  };

  const exportCsv = () => {
    if (!card) return;
    const lines = [csvColumns.map(([label]) => label).join(",")];
    for (const entry of card.transaction_history) {
      lines.push(csvColumns.map(([, value]) => csvCell(value(entry))).join(","));
    }
    download("suica_history.csv", lines.join("\r\n"), "text/csv");
  };

  return (
    <CardPanel title="カード情報 JSON">
      <div class="toolbar">
        <button class="ghost" type="button" disabled={!card} onClick={copyJson}>
          JSONをコピー
        </button>
        <button
          class="ghost"
          type="button"
          disabled={!card}
          onClick={() =>
            card && download("suica_card.json", JSON.stringify(card, null, 2), "application/json")
          }
        >
          JSONを保存
        </button>
        <button class="ghost" type="button" disabled={!card} onClick={exportCsv}>
          履歴をCSVで保存
        </button>
      </div>
      <pre class="json">
        {card ? JSON.stringify(card, null, 2) : "// カードが読み取られていません"}
      </pre>
    </CardPanel>
  );
}

function initialTheme(): Theme {
  const stored = localStorage.getItem("suica-theme");
  return stored === "light" || stored === "dark" || stored === "system" ? stored : "system";
}

export function App() {
  const [activeTab, setActiveTab] = useState<Tab>("overview");
  const [card, setCard] = useState<CardData | null>(null);
  const [readAt, setReadAt] = useState<string | null>(null);
  const [readerState, setReaderState] = useState<ReaderState>("initializing");
  const [statusMessage, setStatusMessage] = useState("接続しています…");
  const [progress, setProgress] = useState(0);
  const [theme, setTheme] = useState<Theme>(initialTheme);

  useEffect(() => {
    if (theme === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.dataset.theme = theme;
    localStorage.setItem("suica-theme", theme);
  }, [theme]);

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
          setProgress(event.value);
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
  }, []);

  const systemIsDark = matchMedia("(prefers-color-scheme: dark)").matches;
  const isDark = theme === "dark" || (theme === "system" && systemIsDark);
  const updateStatus = (state: ReaderState, message: string) => {
    setReaderState(state);
    setStatusMessage(message);
  };

  return (
    <main class="wrap">
      <header class="top">
        <h1>Suica Viewer</h1>
        <span class="status" role="status">
          <span class={`dot ${readerState}`} aria-hidden="true" />
          <span>{statusMessage}</span>
        </span>
        <span class="spacer" />
        <span class="meta">読取日時: {readAt || "—"}</span>
        <button
          class="ghost"
          type="button"
          title="テーマ切替"
          onClick={() => setTheme(isDark ? "light" : "dark")}
        >
          {isDark ? "☀ ライト" : "🌙 ダーク"}
        </button>
      </header>

      <div class={`progress ${progress > 0 && progress < 100 ? "" : "idle"}`}>
        <i style={{ width: `${Math.max(0, Math.min(100, progress))}%` }} />
      </div>

      <nav class="tabs" role="tablist" aria-label="カード情報">
        {tabs.map((tab) => (
          <button
            type="button"
            role="tab"
            id={`tab-${tab.id}`}
            aria-controls={`panel-${tab.id}`}
            aria-selected={activeTab === tab.id}
            onClick={() => setActiveTab(tab.id)}
            key={tab.id}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <section role="tabpanel" id={`panel-${activeTab}`} aria-labelledby={`tab-${activeTab}`}>
        {activeTab === "overview" && <Overview card={card} />}
        {activeTab === "cardinfo" && <CardInfo card={card} />}
        {activeTab === "history" && <History card={card} />}
        {activeTab === "gates" && <Gates card={card} />}
        {activeTab === "data" && <DataView card={card} setStatus={updateStatus} />}
      </section>
    </main>
  );
}
