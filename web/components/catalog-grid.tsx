"use client";

import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api } from "@/lib/api";
import { CatalogCard } from "./catalog-card";

export function CatalogGrid() {
  const [filter, setFilter] = useState("");
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["catalog"],
    queryFn: () => api.listCatalog(),
  });

  const filtered = useMemo(() => {
    if (!data) return [];
    const q = filter.trim().toLowerCase();
    if (!q) return data;
    return data.filter((e) =>
      [e.vendor, e.product, e.version, e.log_type, e.format]
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }, [data, filter]);

  return (
    <section className="space-y-6">
      <div className="flex items-center gap-4">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="搜尋廠牌、產品、log 類型…"
          className="flex-1 max-w-md bg-[var(--color-surface)] border border-[var(--color-line)] rounded-md px-3 py-2 text-sm text-[var(--color-fg)] placeholder:text-[var(--color-fg-faint)] focus:outline-none focus:border-[var(--color-accent)] transition-colors"
        />
        <span className="text-[11px] uppercase tracking-wider text-[var(--color-fg-faint)] font-mono">
          {filtered.length} / {data?.length ?? 0} 筆規格
        </span>
      </div>

      {isLoading ? (
        <SkeletonGrid />
      ) : isError ? (
        <div className="border border-[var(--color-err)]/50 bg-[var(--color-err)]/10 rounded-lg p-6 text-sm text-[var(--color-err)]">
          目錄載入失敗:{(error as Error).message}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map((e) => (
            <CatalogCard
              key={`${e.vendor}/${e.product}/${e.version}/${e.log_type}`}
              entry={e}
            />
          ))}
        </div>
      )}
    </section>
  );
}

function SkeletonGrid() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
      {Array.from({ length: 6 }).map((_, i) => (
        <div
          key={i}
          className="h-44 bg-[var(--color-surface)] border border-[var(--color-line)] rounded-lg animate-pulse"
        />
      ))}
    </div>
  );
}
