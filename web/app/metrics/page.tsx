"use client";

import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/page-header";
import { api, type MetricsResponse } from "@/lib/api";

export default function MetricsPage() {
  const { data, isLoading, isError, error } = useQuery<MetricsResponse>({
    queryKey: ["cti-metrics"],
    queryFn: api.ctiMetrics,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-10">
      <PageHeader
        eyebrow="CTI 指標"
        title="Time-to-Catalog(情報到偵測資產耗時)"
        subtitle="從 advisory `cti.ingested_at` 到 catalog 第一筆 git commit 的天數差 — Mythos-ready R10 衡量「情報多快變成偵測資產」的指標。越小越好,當日落地為目標。"
      />

      {isLoading ? (
        <div className="h-16 flex items-center text-[var(--color-fg-faint)] font-mono text-sm">
          載入中…
        </div>
      ) : isError ? (
        <div className="border border-[var(--color-err)]/50 bg-[var(--color-err)]/10 rounded-lg p-6 text-sm text-[var(--color-err)]">
          指標載入失敗:{(error as Error)?.message ?? "unknown"}
        </div>
      ) : data ? (
        <Body data={data} />
      ) : null}
    </div>
  );
}

function Body({ data }: { data: MetricsResponse }) {
  const { summary, catalogs } = data;

  if (catalogs.length === 0) {
    return (
      <div className="border border-dashed border-[var(--color-line)] rounded-lg p-12 text-center">
        <div className="text-[var(--color-fg-muted)] font-mono text-sm">
          尚無 catalog 設置 <code>cti.ingested_at</code>。
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <SummaryCards summary={summary} />
      {summary.measured_count === 0 ? <GitUnavailableHint /> : null}
      <MetricsTable catalogs={catalogs} />
    </div>
  );
}

function SummaryCards({ summary }: { summary: MetricsResponse["summary"] }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
      <Card label="catalog 數" value={String(summary.catalog_count)} />
      <Card
        label="P0"
        value={String(summary.p0_count)}
        accent={summary.p0_count > 0}
      />
      <Card
        label="當日落地"
        value={String(summary.same_day_count)}
        accent={summary.same_day_count > 0}
      />
      <Card
        label="中位數(天)"
        value={
          summary.median_delta_days === null
            ? "—"
            : summary.median_delta_days.toString()
        }
      />
      <Card
        label="最大(天)"
        value={summary.max_delta_days === null ? "—" : String(summary.max_delta_days)}
      />
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

function GitUnavailableHint() {
  return (
    <div className="border border-[var(--color-warn)]/40 bg-[var(--color-warn)]/10 rounded-md p-4 text-sm">
      <div className="font-mono text-xs uppercase tracking-wider text-[var(--color-warn)] mb-1">
        提醒
      </div>
      <div className="text-[var(--color-fg-muted)]">
        此 API 容器無 <code>.git/</code> 目錄,無法計算 first-commit 時間戳。請在 dev 機器或 CI 跑{" "}
        <code className="text-[var(--color-fg)]">cyberrange cti metrics</code>{" "}
        看真實的 Time-to-Catalog delta。
      </div>
    </div>
  );
}

function MetricsTable({
  catalogs,
}: {
  catalogs: MetricsResponse["catalogs"];
}) {
  return (
    <div className="border border-[var(--color-line)] rounded-lg overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-[var(--color-surface)]/60">
          <tr className="text-left text-[11px] uppercase tracking-wider text-[var(--color-fg-muted)] font-mono">
            <th className="px-4 py-3 w-12">優先</th>
            <th className="px-4 py-3 w-24">Delta</th>
            <th className="px-4 py-3">情報抓入 → catalog commit</th>
            <th className="px-4 py-3">Advisory</th>
            <th className="px-4 py-3">Catalog</th>
          </tr>
        </thead>
        <tbody>
          {catalogs.map((m) => (
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
                <DeltaPill delta={m.delta_days} />
              </td>
              <td className="px-4 py-3 align-top font-mono text-xs text-[var(--color-fg-muted)]">
                {m.ingested_at ?? "?"} → {m.first_commit_at ?? "?"}
              </td>
              <td className="px-4 py-3 align-top font-mono text-xs text-[var(--color-fg-muted)]">
                <div>{m.advisory_id ?? "—"}</div>
                {m.related_campaign ? (
                  <div className="text-[var(--color-fg-faint)] mt-0.5">
                    campaign: {m.related_campaign}
                  </div>
                ) : null}
              </td>
              <td className="px-4 py-3 align-top font-mono text-[13px] break-all">
                {m.path}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DeltaPill({ delta }: { delta: number | null }) {
  if (delta === null) {
    return (
      <span className="text-[var(--color-fg-faint)] font-mono text-xs">
        n/a
      </span>
    );
  }
  let cls = "bg-[var(--color-surface-2)]/50 text-[var(--color-fg-muted)]";
  if (delta === 0)
    cls = "bg-[var(--color-accent)]/15 text-[var(--color-accent)]";
  else if (delta <= 2)
    cls = "bg-[var(--color-warn)]/15 text-[var(--color-warn)]";
  else cls = "bg-[var(--color-err)]/15 text-[var(--color-err)]";

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold ${cls}`}
    >
      {delta}d
    </span>
  );
}
