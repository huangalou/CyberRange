import Link from "next/link";
import type { CatalogEntry } from "@/lib/api";
import { vendorToken, vendorVar } from "@/lib/vendors";
import { FormatChip } from "./format-chip";

export function CatalogCard({ entry }: { entry: CatalogEntry }) {
  const t = vendorToken(entry.vendor);
  const href = `/catalog/${entry.vendor}/${entry.product}/${entry.version}/${entry.log_type}`;

  return (
    <Link
      href={href}
      className="group relative flex bg-[var(--color-surface)] border border-[var(--color-line)] rounded-lg overflow-hidden hover:border-[var(--color-line-strong)] transition-colors hover:-translate-y-0.5 hover:shadow-[0_8px_24px_oklch(0%_0_0/0.4)] duration-200 will-change-transform"
      style={vendorVar(entry.vendor)}
    >
      <div className="vendor-rail w-1 shrink-0" />
      <div className="flex-1 p-5 space-y-4 min-w-0">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1 min-w-0">
            <div
              className="text-[10px] uppercase tracking-[0.22em] font-mono vendor-text"
            >
              {t.label} · {entry.product}
            </div>
            <h3 className="font-mono text-base font-medium truncate">
              {entry.log_type}
            </h3>
            <div className="text-[11px] text-[var(--color-fg-faint)] font-mono">
              v{entry.version}
            </div>
          </div>
          <FormatChip format={entry.format} />
        </div>

        {entry.description ? (
          <p className="text-[12.5px] leading-relaxed text-[var(--color-fg-muted)] line-clamp-3">
            {entry.description.split("\n")[0]}
          </p>
        ) : null}

        <div className="flex items-center gap-2 pt-1">
          {entry.transport.map((tr) => (
            <span
              key={tr}
              className="text-[10px] font-mono text-[var(--color-fg-faint)] border border-[var(--color-line)] rounded px-1.5 py-0.5"
            >
              {tr}
            </span>
          ))}
        </div>

        <div className="flex items-center justify-between pt-2 border-t border-[var(--color-line)]/60">
          <span className="text-[11px] uppercase tracking-wider text-[var(--color-fg-faint)]">
            開啟規格
          </span>
          <span className="text-[var(--color-accent)] font-mono text-sm group-hover:translate-x-0.5 transition-transform">
            →
          </span>
        </div>
      </div>
    </Link>
  );
}
