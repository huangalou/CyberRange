"use client";

import { useState } from "react";
import type {
  CefExtensionOverride,
  CefExtensionOverrideMap,
  CefMappingEntry,
} from "@/lib/api";

interface CefExtensionsTableProps {
  mapping: CefMappingEntry[];
  overrides: CefExtensionOverrideMap;
  onChange: (next: CefExtensionOverrideMap) => void;
}

function isOverridden(ov: CefExtensionOverride | undefined): boolean {
  if (!ov) return false;
  return (
    (ov.cef_key !== undefined && ov.cef_key !== "") ||
    (ov.value !== undefined && ov.value !== "")
  );
}

export function CefExtensionsTable({
  mapping,
  overrides,
  onChange,
}: CefExtensionsTableProps) {
  // Ad-hoc rows = override entries whose pa_field isn't in the catalog mapping.
  // Tracked here so the row stays visible while user fills it in.
  const [adhocPaFields, setAdhocPaFields] = useState<string[]>([]);

  function setRow(paField: string, patch: Partial<CefExtensionOverride>) {
    const next: CefExtensionOverrideMap = { ...overrides };
    const merged = { ...(next[paField] ?? {}), ...patch };
    if (merged.cef_key === "") delete merged.cef_key;
    if (merged.value === "") delete merged.value;
    if (Object.keys(merged).length === 0) {
      delete next[paField];
    } else {
      next[paField] = merged;
    }
    onChange(next);
  }

  function resetRow(paField: string) {
    const next: CefExtensionOverrideMap = { ...overrides };
    delete next[paField];
    onChange(next);
    setAdhocPaFields((prev) => prev.filter((p) => p !== paField));
  }

  function resetAll() {
    onChange({});
    setAdhocPaFields([]);
  }

  function addAdhoc() {
    const stamp = Date.now().toString(36).slice(-4);
    const candidate = `custom_${stamp}`;
    setAdhocPaFields((prev) => [...prev, candidate]);
  }

  function renameAdhoc(oldField: string, newField: string) {
    if (oldField === newField || newField.trim() === "") return;
    const next: CefExtensionOverrideMap = { ...overrides };
    if (oldField in next) {
      next[newField] = next[oldField];
      delete next[oldField];
      onChange(next);
    }
    setAdhocPaFields((prev) =>
      prev.map((p) => (p === oldField ? newField : p)),
    );
  }

  const changedCount = Object.values(overrides).filter(isOverridden).length;

  const adhocVisible = adhocPaFields.filter(
    (f) => !mapping.some((m) => m.pa_field === f),
  );

  return (
    <section className="bg-[var(--color-surface)] border border-[var(--color-line)] rounded-lg overflow-hidden">
      <div className="flex items-center justify-between gap-3 px-5 py-3 border-b border-[var(--color-line)] bg-[var(--color-surface-2)]/40">
        <div className="text-[11px] uppercase tracking-[0.22em] font-mono text-[var(--color-accent-2)]">
          CEF Extensions Mapping
        </div>
        <div className="flex items-center gap-3 text-[10.5px] font-mono">
          {changedCount > 0 ? (
            <>
              <span className="text-[var(--color-accent)]">
                {changedCount} 列已覆寫
              </span>
              <button
                type="button"
                onClick={resetAll}
                className="text-[var(--color-fg-muted)] hover:text-[var(--color-fg)] uppercase tracking-wider"
              >
                ↻ 全部重設
              </button>
            </>
          ) : (
            <span className="text-[var(--color-fg-faint)]">
              沿用 PA 10.0 手冊預設
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-[minmax(140px,1fr)_minmax(140px,1fr)_minmax(160px,1fr)_28px] gap-2 px-5 py-2 border-b border-[var(--color-line)]/50 text-[10px] uppercase tracking-wider font-mono text-[var(--color-fg-faint)]">
        <span>PA Field</span>
        <span>CEF Key</span>
        <span>Value 覆寫</span>
        <span />
      </div>

      <div className="divide-y divide-[var(--color-line)]/40 max-h-[520px] overflow-y-auto">
        {mapping.map((row) => {
          const ov = overrides[row.pa_field];
          const dirty = isOverridden(ov);
          return (
            <div
              key={row.pa_field}
              className="grid grid-cols-[minmax(140px,1fr)_minmax(140px,1fr)_minmax(160px,1fr)_28px] gap-2 px-5 py-2 items-center text-[12px] mono"
            >
              <span className="text-[var(--color-fg)] flex items-center gap-2 truncate">
                {dirty ? (
                  <span className="text-[var(--color-accent)]">●</span>
                ) : null}
                {row.pa_field}
              </span>
              <input
                value={ov?.cef_key ?? ""}
                placeholder={row.cef_key}
                onChange={(e) => setRow(row.pa_field, { cef_key: e.target.value })}
                className="bg-[var(--color-bg)] border border-[var(--color-line)] rounded-md px-2 py-1 mono focus:outline-none focus:border-[var(--color-accent)]"
              />
              <input
                value={ov?.value ?? ""}
                placeholder="(auto from generator)"
                onChange={(e) => setRow(row.pa_field, { value: e.target.value })}
                className="bg-[var(--color-bg)] border border-[var(--color-line)] rounded-md px-2 py-1 mono focus:outline-none focus:border-[var(--color-accent)]"
              />
              <button
                type="button"
                disabled={!dirty}
                onClick={() => resetRow(row.pa_field)}
                title="重設此列"
                className="text-[var(--color-fg-muted)] hover:text-[var(--color-fg)] disabled:opacity-30 disabled:cursor-not-allowed text-[14px] leading-none"
              >
                ↻
              </button>
            </div>
          );
        })}

        {adhocVisible.length > 0 ? (
          <div className="px-5 py-1.5 text-[10px] uppercase tracking-wider font-mono text-[var(--color-fg-faint)] bg-[var(--color-surface-2)]/30">
            自訂欄位(mapping 外,需同時填 CEF Key + Value 才會送出)
          </div>
        ) : null}

        {adhocVisible.map((field) => {
          const ov = overrides[field] ?? {};
          return (
            <div
              key={field}
              className="grid grid-cols-[minmax(140px,1fr)_minmax(140px,1fr)_minmax(160px,1fr)_28px] gap-2 px-5 py-2 items-center text-[12px] mono"
            >
              <input
                value={field}
                onChange={(e) => renameAdhoc(field, e.target.value)}
                placeholder="custom_field"
                className="bg-[var(--color-bg)] border border-[var(--color-line)] rounded-md px-2 py-1 mono focus:outline-none focus:border-[var(--color-accent)]"
              />
              <input
                value={ov.cef_key ?? ""}
                placeholder="cs10"
                onChange={(e) => setRow(field, { cef_key: e.target.value })}
                className="bg-[var(--color-bg)] border border-[var(--color-line)] rounded-md px-2 py-1 mono focus:outline-none focus:border-[var(--color-accent)]"
              />
              <input
                value={ov.value ?? ""}
                placeholder="raw value"
                onChange={(e) => setRow(field, { value: e.target.value })}
                className="bg-[var(--color-bg)] border border-[var(--color-line)] rounded-md px-2 py-1 mono focus:outline-none focus:border-[var(--color-accent)]"
              />
              <button
                type="button"
                onClick={() => resetRow(field)}
                title="移除此自訂欄位"
                className="text-[var(--color-fg-muted)] hover:text-[var(--color-err)] text-[14px] leading-none"
              >
                ×
              </button>
            </div>
          );
        })}
      </div>

      <div className="px-5 py-3 border-t border-[var(--color-line)]/50 bg-[var(--color-surface-2)]/40">
        <button
          type="button"
          onClick={addAdhoc}
          className="text-[11px] uppercase tracking-wider font-mono text-[var(--color-accent)] hover:text-[var(--color-fg)]"
        >
          + 新增自訂 mapping
        </button>
      </div>
    </section>
  );
}
