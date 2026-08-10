"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/page-header";
import { api, type VulnOpsQueryResponse } from "@/lib/api";

type Field = "cve" | "advisory" | "package" | "campaign";

const FIELDS: { key: Field; label: string; placeholder: string }[] = [
  { key: "cve",      label: "CVE",      placeholder: "CVE-2026-0001" },
  { key: "advisory", label: "Advisory", placeholder: "PYSEC-2026-2" },
  { key: "package",  label: "Package",  placeholder: "pypi:litellm:1.82.8" },
  { key: "campaign", label: "Campaign", placeholder: "teampcp" },
];

function splitTokens(raw: string): string[] {
  return raw
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function hasAnyInput(values: Record<Field, string>): boolean {
  return FIELDS.some((f) => splitTokens(values[f.key]).length > 0);
}

export default function VulnOpsPage() {
  const [values, setValues] = useState<Record<Field, string>>({
    cve: "",
    advisory: "",
    package: "",
    campaign: "",
  });
  const [submitted, setSubmitted] = useState<Record<Field, string[]> | null>(
    null,
  );

  const { data, isFetching, isError, error } = useQuery<VulnOpsQueryResponse>({
    queryKey: ["vulnops", submitted],
    queryFn: () =>
      api.vulnopsQuery({
        cve: submitted?.cve,
        advisory: submitted?.advisory,
        package: submitted?.package,
        campaign: submitted?.campaign,
      }),
    enabled: submitted !== null,
  });

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!hasAnyInput(values)) return;
    setSubmitted({
      cve: splitTokens(values.cve),
      advisory: splitTokens(values.advisory),
      package: splitTokens(values.package),
      campaign: splitTokens(values.campaign),
    });
  }

  function onReset() {
    setValues({ cve: "", advisory: "", package: "", campaign: "" });
    setSubmitted(null);
  }

  return (
    <div className="space-y-10">
      <PageHeader
        eyebrow="弱點反查"
        title="從漏洞反查 catalog 覆蓋"
        subtitle="輸入 CVE / advisory / package / campaign,反查已涵蓋這些情報的 catalog。多欄位走聯集(任一關鍵字命中即列出);`matched_by` 標記為什麼這筆結果落到清單裡。"
      />

      <form
        onSubmit={onSubmit}
        className="grid gap-4 md:grid-cols-2 border border-[var(--color-line)] rounded-lg p-6 bg-[var(--color-surface)]/40"
      >
        {FIELDS.map((f) => (
          <label key={f.key} className="space-y-2">
            <span className="text-[11px] uppercase tracking-wider text-[var(--color-fg-muted)] font-mono">
              {f.label}
              <span className="text-[var(--color-fg-faint)] normal-case ml-2">
                (逗號或換行分隔)
              </span>
            </span>
            <input
              type="text"
              value={values[f.key]}
              onChange={(e) =>
                setValues((v) => ({ ...v, [f.key]: e.target.value }))
              }
              placeholder={f.placeholder}
              className="w-full px-3 py-2 rounded-md bg-[var(--color-bg)]/60 border border-[var(--color-line)] hover:border-[var(--color-line-strong)] focus:border-[var(--color-accent)] focus:outline-none font-mono text-sm transition-colors"
            />
          </label>
        ))}

        <div className="md:col-span-2 flex items-center gap-3 pt-2">
          <button
            type="submit"
            disabled={!hasAnyInput(values) || isFetching}
            className="px-6 py-2.5 rounded-md bg-[var(--color-accent)] text-[var(--color-bg)] font-semibold text-sm hover:brightness-110 active:scale-[0.98] transition disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {isFetching ? "查詢中…" : "▶ 反查"}
          </button>
          <button
            type="button"
            onClick={onReset}
            className="px-4 py-2.5 rounded-md border border-[var(--color-line)] hover:border-[var(--color-line-strong)] text-sm text-[var(--color-fg-muted)] hover:text-[var(--color-fg)] transition-colors"
          >
            重設
          </button>
          {submitted && !hasAnyInput(values) ? (
            <span className="text-[var(--color-fg-faint)] text-xs ml-2">
              按重設以清空結果。
            </span>
          ) : null}
        </div>
      </form>

      {submitted === null ? (
        <EmptyHint />
      ) : isError ? (
        <ErrorBlock message={(error as Error)?.message ?? "query failed"} />
      ) : data ? (
        <Results data={data} />
      ) : (
        <div className="h-16 flex items-center text-[var(--color-fg-faint)] font-mono text-sm">
          載入中…
        </div>
      )}
    </div>
  );
}

function EmptyHint() {
  return (
    <div className="border border-dashed border-[var(--color-line)] rounded-lg p-12 text-center">
      <div className="text-[var(--color-fg-muted)] font-mono text-sm">
        至少輸入一個關鍵字,按反查。
      </div>
      <div className="text-[var(--color-fg-faint)] text-xs mt-2">
        範例:<code>campaign = teampcp</code> →
        跨 endpoint / host / k8s / cloud / perimeter 6 份 TeamPCP catalog。
      </div>
    </div>
  );
}

function ErrorBlock({ message }: { message: string }) {
  return (
    <div className="border border-[var(--color-err)]/50 bg-[var(--color-err)]/10 rounded-lg p-6 text-sm text-[var(--color-err)]">
      反查失敗:{message}
    </div>
  );
}

function Results({ data }: { data: VulnOpsQueryResponse }) {
  const { summary, matches } = data;

  if (summary.catalog_count === 0) {
    return (
      <div className="border border-dashed border-[var(--color-line)] rounded-lg p-12 text-center">
        <div className="text-[var(--color-fg-muted)] font-mono text-sm">
          沒有 catalog 命中此次反查。
        </div>
        <div className="text-[var(--color-fg-faint)] text-xs mt-2">
          檢查拼字。若以版本反查,確認該版本落在 catalog{" "}
          <code>vulnops.affects[].version_range</code> 範圍內。
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <SummaryCards summary={summary} />
      <MatchTable matches={matches} />
    </div>
  );
}

function SummaryCards({
  summary,
}: {
  summary: VulnOpsQueryResponse["summary"];
}) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      <Card label="命中 catalog" value={String(summary.catalog_count)} />
      <Card
        label="P0(回歸關鍵)"
        value={String(summary.p0_count)}
        accent={summary.p0_count > 0}
      />
      <Card label="Advisory 數" value={String(Object.keys(summary.by_advisory).length)} />
      <Card label="Campaign 數" value={String(Object.keys(summary.by_campaign).length)} />
    </div>
  );
}

function Card({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent?: boolean;
}) {
  return (
    <div className="border border-[var(--color-line)] rounded-md p-4 bg-[var(--color-surface)]/40">
      <div className="text-[10px] uppercase tracking-wider text-[var(--color-fg-faint)] font-mono">
        {label}
      </div>
      <div
        className={`mt-1 text-2xl font-semibold tracking-tight ${
          accent ? "text-[var(--color-accent)]" : ""
        }`}
      >
        {value}
      </div>
    </div>
  );
}

function MatchTable({
  matches,
}: {
  matches: VulnOpsQueryResponse["matches"];
}) {
  return (
    <div className="border border-[var(--color-line)] rounded-lg overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-[var(--color-surface)]/60">
          <tr className="text-left text-[11px] uppercase tracking-wider text-[var(--color-fg-muted)] font-mono">
            <th className="px-4 py-3 w-12">優先</th>
            <th className="px-4 py-3">Catalog</th>
            <th className="px-4 py-3">Advisory</th>
            <th className="px-4 py-3">命中關鍵字</th>
          </tr>
        </thead>
        <tbody>
          {matches.map((m) => (
            <tr
              key={m.path}
              className="border-t border-[var(--color-line)] hover:bg-[var(--color-surface-2)]/30"
            >
              <td className="px-4 py-3 align-top">
                {m.regression_critical ? (
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--color-err)]/15 text-[var(--color-err)] font-mono">
                    P0
                  </span>
                ) : (
                  <span className="text-[var(--color-fg-faint)] font-mono text-xs">
                    —
                  </span>
                )}
              </td>
              <td className="px-4 py-3 align-top">
                <div className="font-mono text-[13px] break-all">
                  {m.path}
                </div>
                <div className="text-[var(--color-fg-faint)] text-xs mt-0.5">
                  {m.vendor} / {m.product} / {m.version}
                </div>
              </td>
              <td className="px-4 py-3 align-top font-mono text-xs text-[var(--color-fg-muted)]">
                <div>{m.advisory_id ?? "—"}</div>
                {m.related_campaign ? (
                  <div className="text-[var(--color-fg-faint)] mt-0.5">
                    campaign: {m.related_campaign}
                  </div>
                ) : null}
              </td>
              <td className="px-4 py-3 align-top">
                <div className="flex flex-wrap gap-1.5">
                  {m.matched_by.map((tok) => (
                    <span
                      key={tok}
                      className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-[var(--color-accent)]/15 text-[var(--color-accent)] border border-[var(--color-accent)]/30"
                    >
                      {tok}
                    </span>
                  ))}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
