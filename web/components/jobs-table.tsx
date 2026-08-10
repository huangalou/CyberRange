"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { VendorBadge } from "./vendor-badge";
import { JobStatusPill } from "./job-status-pill";

function fmtTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour12: false });
}

function fmtDuration(start: string | null, end: string | null): string {
  if (!start || !end) return "—";
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

export function JobsTable() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["jobs"],
    queryFn: api.listJobs,
    refetchInterval: 1500,
  });

  if (isLoading) {
    return (
      <div className="h-32 flex items-center justify-center text-[var(--color-fg-faint)] font-mono text-sm">
        載入中…
      </div>
    );
  }
  if (isError) {
    return (
      <div className="border border-[var(--color-err)]/50 bg-[var(--color-err)]/10 rounded-lg p-6 text-sm text-[var(--color-err)]">
        工作列表載入失敗。
      </div>
    );
  }

  const sorted = (data ?? [])
    .slice()
    .sort((a, b) =>
      (b.started_at ?? b.id).localeCompare(a.started_at ?? a.id),
    );

  if (sorted.length === 0) {
    return (
      <div className="border border-dashed border-[var(--color-line)] rounded-lg p-12 text-center">
        <div className="text-[var(--color-fg-muted)] font-mono text-sm">
          尚未派送任何工作。
        </div>
        <div className="text-[var(--color-fg-faint)] text-xs mt-1">
          至 Log 目錄選一筆規格,按下「▶ 派送」開始。
        </div>
      </div>
    );
  }

  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-line)] rounded-lg overflow-x-auto">
      <table className="w-full min-w-[760px] text-sm">
        <thead className="bg-[var(--color-surface-2)]/40">
          <tr className="text-left text-[10px] uppercase tracking-[0.16em] font-mono text-[var(--color-fg-muted)]">
            <th className="px-4 py-2.5">狀態</th>
            <th className="px-4 py-2.5">規格</th>
            <th className="px-4 py-2.5 text-right">已送 / 總數</th>
            <th className="px-4 py-2.5">Sink</th>
            <th className="px-4 py-2.5">開始時間</th>
            <th className="px-4 py-2.5">耗時</th>
            <th className="px-4 py-2.5">ID</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((j) => (
            <tr
              key={j.id}
              className="border-t border-[var(--color-line)] hover:bg-[var(--color-surface-2)]/30 transition-colors"
            >
              <td className="px-4 py-3">
                <JobStatusPill status={j.status} />
              </td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-2">
                  <VendorBadge vendor={j.spec.vendor} />
                  <span className="font-mono text-[12px] text-[var(--color-fg-muted)]">
                    {j.spec.product}/{j.spec.version}/{j.spec.log_type}
                  </span>
                </div>
              </td>
              <td className="px-4 py-3 text-right mono text-[12px]">
                <span
                  className={
                    j.status === "completed"
                      ? "text-[var(--color-ok)]"
                      : j.status === "running"
                        ? "text-[var(--color-info)]"
                        : "text-[var(--color-fg-muted)]"
                  }
                >
                  {j.sent}
                </span>
                <span className="text-[var(--color-fg-faint)]">/{j.count}</span>
              </td>
              <td className="px-4 py-3 mono text-[12px] text-[var(--color-fg-muted)] truncate max-w-[260px]">
                {j.sink}
              </td>
              <td className="px-4 py-3 mono text-[12px] text-[var(--color-fg-muted)]">
                {fmtTime(j.started_at)}
              </td>
              <td className="px-4 py-3 mono text-[12px] text-[var(--color-fg-muted)]">
                {fmtDuration(j.started_at, j.completed_at)}
              </td>
              <td className="px-4 py-3 mono text-[11px] text-[var(--color-fg-faint)]">
                {j.id.slice(0, 8)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
