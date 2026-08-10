"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

const NAV = [
  { href: "/", label: "Log 目錄", hint: "Catalog", glyph: "▤" },
  { href: "/jobs", label: "派送工作", hint: "Jobs", glyph: "▶" },
  { href: "/vulnops", label: "弱點反查", hint: "VulnOps", glyph: "◆" },
  { href: "/metrics", label: "CTI 指標", hint: "Metrics", glyph: "◷" },
];

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <Link href="/" className="block group">
      <div className="flex items-baseline">
        <span className="text-[var(--color-accent)] font-mono font-bold text-lg tracking-tight">
          Cyber
        </span>
        <span className="font-mono font-bold text-lg tracking-tight">Range</span>
      </div>
      {compact ? null : (
        <div className="text-[12px] text-[var(--color-fg-muted)] mt-0.5 leading-tight">
          攻防演練平台
        </div>
      )}
    </Link>
  );
}

export function Sidebar() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (open) {
      const prev = document.body.style.overflow;
      document.body.style.overflow = "hidden";
      return () => {
        document.body.style.overflow = prev;
      };
    }
  }, [open]);

  const { data: health, isError: healthErr } = useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: 5_000,
  });

  return (
    <>
      <div className="md:hidden fixed top-0 inset-x-0 h-14 bg-[var(--color-bg)]/95 backdrop-blur border-b border-[var(--color-line)] z-40 flex items-center justify-between px-4">
        <Brand compact />
        <button
          aria-label="開啟導覽選單"
          onClick={() => setOpen(true)}
          className="w-10 h-10 inline-flex items-center justify-center rounded-md border border-[var(--color-line)] hover:border-[var(--color-line-strong)] active:scale-95 transition"
        >
          <span className="text-[var(--color-fg)] text-lg leading-none">≡</span>
        </button>
      </div>

      <div
        onClick={() => setOpen(false)}
        className={`md:hidden fixed inset-0 bg-black/65 backdrop-blur-sm z-40 transition-opacity ${
          open ? "opacity-100" : "opacity-0 pointer-events-none"
        }`}
        aria-hidden="true"
      />

      <aside
        className={`fixed left-0 top-0 bottom-0 w-[240px] z-50 border-r border-[var(--color-line)] bg-[var(--color-surface)]/95 md:bg-[var(--color-surface)]/40 backdrop-blur flex flex-col transform transition-transform ${
          open ? "translate-x-0" : "-translate-x-full"
        } md:translate-x-0`}
      >
        <div className="px-5 py-6 border-b border-[var(--color-line)] flex items-start justify-between">
          <Brand />
          <button
            aria-label="關閉導覽選單"
            onClick={() => setOpen(false)}
            className="md:hidden w-8 h-8 inline-flex items-center justify-center rounded-md text-[var(--color-fg-muted)] hover:text-[var(--color-fg)]"
          >
            ✕
          </button>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1" aria-label="主導覽">
          {NAV.map((n) => {
            const active =
              n.href === "/" ? pathname === "/" : pathname.startsWith(n.href);
            return (
              <Link
                key={n.href}
                href={n.href}
                onClick={() => setOpen(false)}
                className={`group flex items-center gap-3 px-3 py-2.5 rounded-md text-sm transition-colors ${
                  active
                    ? "bg-[var(--color-surface-2)] text-[var(--color-fg)]"
                    : "text-[var(--color-fg-muted)] hover:text-[var(--color-fg)] hover:bg-[var(--color-surface-2)]/50"
                }`}
              >
                <span
                  className={`w-1 h-4 rounded-full ${
                    active ? "bg-[var(--color-accent)]" : "bg-transparent"
                  }`}
                />
                <span className="font-mono text-xs opacity-60">{n.glyph}</span>
                <span className="flex-1">{n.label}</span>
                <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-[var(--color-fg-faint)]/80">
                  {n.hint}
                </span>
              </Link>
            );
          })}
        </nav>

        <div className="px-4 py-4 border-t border-[var(--color-line)]">
          <div className="flex items-center gap-2 text-[11px]">
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                healthErr
                  ? "bg-[var(--color-err)]"
                  : health
                    ? "bg-[var(--color-ok)]"
                    : "bg-[var(--color-fg-faint)]"
              }`}
            />
            <span className="text-[var(--color-fg-muted)] uppercase tracking-wider">
              API
            </span>
            <span className="text-[var(--color-fg-faint)] font-mono ml-auto">
              {healthErr ? "離線" : (health?.version ?? "…")}
            </span>
          </div>
        </div>
      </aside>
    </>
  );
}
