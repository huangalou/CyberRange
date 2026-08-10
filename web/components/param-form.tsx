"use client";

import { useEffect, useState } from "react";

type Props = {
  defaults: Record<string, unknown>;
  onChange: (params: Record<string, string>) => void;
};

export function ParamForm({ defaults, onChange }: Props) {
  // Initialize state from defaults — stringify lists/objects for textarea editing.
  const [values, setValues] = useState<Record<string, string>>(() => {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(defaults)) {
      out[k] =
        typeof v === "string"
          ? v
          : v == null
            ? ""
            : JSON.stringify(v);
    }
    return out;
  });

  useEffect(() => {
    onChange(values);
    // intentionally only when values change
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [values]);

  const keys = Object.keys(defaults);
  if (keys.length === 0) {
    return (
      <p className="text-[12px] text-[var(--color-fg-faint)] font-mono">
        此規格無可調整參數。
      </p>
    );
  }

  return (
    <div className="space-y-3">
      {keys.map((k) => {
        const isList = Array.isArray(defaults[k]);
        return (
          <label key={k} className="block space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase tracking-wider text-[var(--color-fg-muted)] font-mono">
                {k}
              </span>
              {isList ? (
                <span className="text-[10px] text-[var(--color-fg-faint)] font-mono">
                  JSON 陣列
                </span>
              ) : null}
            </div>
            {isList ? (
              <textarea
                rows={2}
                value={values[k] ?? ""}
                onChange={(e) =>
                  setValues((v) => ({ ...v, [k]: e.target.value }))
                }
                className="w-full bg-[var(--color-bg)] border border-[var(--color-line)] rounded-md px-3 py-2 mono text-[var(--color-fg)] focus:outline-none focus:border-[var(--color-accent)]"
              />
            ) : (
              <input
                value={values[k] ?? ""}
                onChange={(e) =>
                  setValues((v) => ({ ...v, [k]: e.target.value }))
                }
                className="w-full bg-[var(--color-bg)] border border-[var(--color-line)] rounded-md px-3 py-2 mono text-[var(--color-fg)] focus:outline-none focus:border-[var(--color-accent)]"
              />
            )}
          </label>
        );
      })}
    </div>
  );
}

/** Parse user input back into JSON-ish for the API: try JSON, fall back to string. */
export function parseParams(
  raw: Record<string, string>,
  defaults: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (Array.isArray(defaults[k]) || (defaults[k] && typeof defaults[k] === "object")) {
      try {
        out[k] = JSON.parse(v);
      } catch {
        out[k] = v;
      }
    } else {
      out[k] = v;
    }
  }
  return out;
}
