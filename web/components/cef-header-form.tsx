"use client";

import type { CefHeader, CefHeaderOverride } from "@/lib/api";

interface CefHeaderFormProps {
  defaults: CefHeader;
  overrides: CefHeaderOverride;
  onChange: (next: CefHeaderOverride) => void;
}

type FieldKey = keyof CefHeader;

const FIELDS: { key: FieldKey; label: string; type: "text" | "number" }[] = [
  { key: "device_vendor",  label: "Device Vendor",  type: "text" },
  { key: "device_product", label: "Device Product", type: "text" },
  { key: "device_version", label: "Device Version", type: "text" },
  { key: "signature_id",   label: "Signature ID",   type: "text" },
  { key: "name",           label: "Name",           type: "text" },
  { key: "severity",       label: "Severity",       type: "number" },
];

export function CefHeaderForm({
  defaults,
  overrides,
  onChange,
}: CefHeaderFormProps) {
  function setField(key: FieldKey, raw: string) {
    const next: CefHeaderOverride = { ...overrides };
    if (raw.trim() === "") {
      delete next[key];
    } else if (key === "severity") {
      const parsed = parseInt(raw, 10);
      if (!Number.isNaN(parsed)) {
        next.severity = parsed;
      } else {
        delete next.severity;
      }
    } else {
      // Every non-severity field is string-typed on `CefHeader`.
      (next[key] as unknown as string) = raw;
    }
    onChange(next);
  }

  function resetAll() {
    onChange({});
  }

  const changedCount = Object.values(overrides).filter(
    (v) => v !== undefined && v !== null && v !== "",
  ).length;

  return (
    <section className="bg-[var(--color-surface)] border border-[var(--color-line)] rounded-lg p-5 space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div className="text-[11px] uppercase tracking-[0.22em] font-mono text-[var(--color-accent-2)]">
          CEF Header
        </div>
        <div className="flex items-center gap-3 text-[10.5px] font-mono">
          {changedCount > 0 ? (
            <>
              <span className="text-[var(--color-accent)]">
                {changedCount} 個欄位已覆寫
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
            <span className="text-[var(--color-fg-faint)]">沿用 catalog 預設</span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {FIELDS.map((f) => {
          const overrideVal = overrides[f.key];
          const defaultVal = defaults[f.key];
          const isOverridden =
            overrideVal !== undefined && overrideVal !== null && overrideVal !== "";
          const displayVal =
            overrideVal === undefined || overrideVal === null
              ? ""
              : String(overrideVal);
          return (
            <label key={f.key} className="block space-y-1.5">
              <span className="text-[11px] uppercase tracking-wider text-[var(--color-fg-muted)] font-mono flex items-center gap-2">
                {f.label}
                {isOverridden ? (
                  <span className="text-[var(--color-accent)]">●</span>
                ) : null}
              </span>
              <input
                type={f.type}
                value={displayVal}
                placeholder={
                  defaultVal === null || defaultVal === undefined
                    ? "(未設定)"
                    : String(defaultVal)
                }
                onChange={(e) => setField(f.key, e.target.value)}
                className="w-full bg-[var(--color-bg)] border border-[var(--color-line)] rounded-md px-3 py-2 mono focus:outline-none focus:border-[var(--color-accent)]"
              />
            </label>
          );
        })}
      </div>
    </section>
  );
}
