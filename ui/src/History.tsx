import { useMemo, useRef, useState } from "preact/hooks";
import type { CardData, TransactionEntry } from "./types";

type DisplayValue = string | number | null | undefined;

interface HistoryColumn {
  key: string;
  label: string;
  numeric?: boolean;
  value: (entry: TransactionEntry) => DisplayValue;
  sortValue?: (entry: TransactionEntry) => string | number;
}

const dash = (value: DisplayValue) =>
  value === null || value === undefined || value === "" ? "—" : String(value);

const yen = (value: number) => `${value.toLocaleString("ja-JP")} 円`;

const delta = (value: number | null) =>
  value === null ? "—" : `${value > 0 ? "+" : ""}${yen(value)}`;

const station = (entry: TransactionEntry, side: "entry" | "exit") =>
  entry.transaction_type_code === 0x46 ? "—" : dash(entry[`${side}_station`]);

const route = (entry: TransactionEntry) => {
  const start = station(entry, "entry");
  const end = station(entry, "exit");
  return start === "—" && end === "—" ? "—" : `${start} → ${end}`;
};

const historyColumns: HistoryColumn[] = [
  {
    key: "when",
    label: "日時",
    value: (entry) =>
      `${entry.recorded_on} ${entry.transaction_time || ""}`.trim(),
  },
  {
    key: "transaction_type",
    label: "取引種別",
    value: (entry) => entry.transaction_type,
  },
  { key: "pay_type", label: "支払種別", value: (entry) => entry.pay_type },
  {
    key: "gate_instruction_type",
    label: "改札処理",
    value: (entry) => entry.gate_instruction_type,
  },
  {
    key: "entry_station",
    label: "入場駅",
    value: (entry) => station(entry, "entry"),
  },
  {
    key: "exit_station",
    label: "出場駅",
    value: (entry) => station(entry, "exit"),
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

const routeColumn: HistoryColumn = {
  key: "route",
  label: "区間",
  value: route,
};
const summaryColumns = [
  ...historyColumns.filter(
    ({ key }) => key === "when" || key === "transaction_type",
  ),
  routeColumn,
  ...historyColumns.filter(({ key }) => key === "delta" || key === "balance"),
];
const searchableColumns = [...historyColumns, routeColumn];

export function History({ card }: { card: CardData | null }) {
  const [filter, setFilter] = useState("");
  const [showDetails, setShowDetails] = useState(false);
  const [sort, setSort] = useState<{ key: string | null; direction: 1 | -1 }>({
    key: null,
    direction: 1,
  });
  const searchInput = useRef<HTMLInputElement>(null);
  const columns = showDetails ? historyColumns : summaryColumns;
  const query = filter.trim().toLocaleLowerCase("ja");

  const rows = useMemo(() => {
    if (!card) return [];
    const filtered = query
      ? card.transaction_history.filter((entry) =>
          searchableColumns.some((column) =>
            dash(column.value(entry)).toLocaleLowerCase("ja").includes(query),
          ),
        )
      : card.transaction_history.slice();

    const column = searchableColumns.find(({ key }) => key === sort.key);
    if (column) {
      filtered.sort((left, right) => {
        const a = column.sortValue?.(left) ?? dash(column.value(left));
        const b = column.sortValue?.(right) ?? dash(column.value(right));
        if (a === b) return 0;
        const comparison =
          typeof a === "number" && typeof b === "number"
            ? a - b
            : String(a).localeCompare(String(b), "ja");
        return comparison * sort.direction;
      });
    }
    return filtered;
  }, [card, query, sort]);

  const clearSearch = () => {
    setFilter("");
    searchInput.current?.focus();
  };

  const sortBy = (key: string) => {
    setSort((current) =>
      current.key === key
        ? { key, direction: current.direction === 1 ? -1 : 1 }
        : { key, direction: 1 },
    );
  };

  const toggleDetails = (checked: boolean) => {
    const nextColumns = checked ? historyColumns : summaryColumns;
    if (!nextColumns.some(({ key }) => key === sort.key)) {
      setSort({ key: null, direction: 1 });
    }
    setShowDetails(checked);
  };

  return (
    <div class="history-panel">
      <div class="section-heading">
        <h2>取引履歴</h2>
        <p>カードに保存されている利用とチャージの記録です。</p>
      </div>

      {!card ? (
        <div class="empty-state">
          <h3 class="empty-title">カードを読み取ると、履歴を確認できます</h3>
          <p class="empty-description">
            リーダーにカードをかざし、読み取りが終わるまでそのままお待ちください。
          </p>
        </div>
      ) : card.transaction_history.length === 0 ? (
        <div class="empty-state">
          <h3 class="empty-title">取引履歴はありません</h3>
          <p class="empty-description">
            このカードには利用やチャージの記録がありません。利用後にもう一度カードをかざしてください。
          </p>
        </div>
      ) : (
        <>
          <div class="history-controls">
            <div class="search-field" role="search" aria-label="取引履歴">
              <label for="history-search">履歴を検索</label>
              <div class="search-input-row">
                <input
                  id="history-search"
                  ref={searchInput}
                  type="search"
                  placeholder="例：新宿、チャージ、2026-09"
                  aria-describedby="history-search-hint"
                  value={filter}
                  onInput={(event) => setFilter(event.currentTarget.value)}
                />
                <button
                  class="ghost"
                  type="button"
                  disabled={!filter}
                  onClick={clearSearch}
                >
                  検索をクリア
                </button>
              </div>
              <p id="history-search-hint" class="field-hint">
                支払種別や機器など、非表示の詳細列も検索できます。
              </p>
            </div>
            <label class="detail-toggle">
              <input
                type="checkbox"
                checked={showDetails}
                onChange={(event) => toggleDetails(event.currentTarget.checked)}
              />
              <span>詳細列を表示</span>
            </label>
          </div>

          <div class="history-options">
            <p class="result-count" role="status" aria-atomic="true">
              {query
                ? `${rows.length.toLocaleString("ja-JP")} 件 / 全 ${card.transaction_history.length.toLocaleString("ja-JP")} 件`
                : `全 ${rows.length.toLocaleString("ja-JP")} 件`}
            </p>
            {rows.length > 0 && (
              <p id="history-scroll-hint" class="table-hint">
                列名で並べ替え · 表が収まらない場合は横にスクロール
              </p>
            )}
          </div>

          {rows.length === 0 ? (
            <div class="empty-state">
              <h3 class="empty-title">
                「{filter.trim()}」に一致する取引はありません
              </h3>
              <p class="empty-description">
                別の駅名や取引種別を入力するか、検索をクリアしてすべての履歴を表示してください。
              </p>
              <button class="ghost" type="button" onClick={clearSearch}>
                検索をクリア
              </button>
            </div>
          ) : (
            <div
              class="tablewrap"
              role="region"
              aria-label="取引履歴の表"
              aria-describedby="history-scroll-hint"
              tabIndex={0}
            >
              <table
                class={`history-table${showDetails ? " history-table-detailed" : ""}`}
                aria-label="取引履歴"
              >
                <thead>
                  <tr>
                    {columns.map((column) => (
                      <th
                        scope="col"
                        class={column.numeric ? "num" : undefined}
                        key={column.key}
                        aria-sort={
                          sort.key !== column.key
                            ? undefined
                            : sort.direction === 1
                              ? "ascending"
                              : "descending"
                        }
                      >
                        <button
                          class="table-sort"
                          type="button"
                          onClick={() => sortBy(column.key)}
                          aria-label={`${column.label}で${sort.key === column.key && sort.direction === 1 ? "降順" : "昇順"}に並べ替え`}
                        >
                          {column.label}
                          <span class="sort-indicator" aria-hidden="true">
                            {sort.key === column.key
                              ? sort.direction === 1
                                ? "↑"
                                : "↓"
                              : "↕"}
                          </span>
                        </button>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((entry) => (
                    <tr key={entry.index}>
                      {columns.map((column) => {
                        const amountClass =
                          column.key === "delta"
                            ? entry.delta === null || entry.delta === 0
                              ? "amount-neutral"
                              : entry.delta > 0
                                ? "amount-positive"
                                : "amount-negative"
                            : "";
                        return (
                          <td
                            class={
                              [
                                column.numeric ? "num" : "",
                                column.key === "route" ? "route-cell" : "",
                                amountClass,
                              ]
                                .filter(Boolean)
                                .join(" ") || undefined
                            }
                            key={column.key}
                          >
                            {dash(column.value(entry))}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
