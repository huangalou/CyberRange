"use client";

import { useMutation } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import {
  api,
  type CefExtensionOverrideMap,
  type CefHeaderOverride,
  type SpecID,
} from "@/lib/api";

interface PreviewPanelProps {
  spec: SpecID;
  params: Record<string, unknown>;
  count?: number;
  cefHeaderOverrides?: CefHeaderOverride;
  cefExtensionOverrides?: CefExtensionOverrideMap;
}

export function PreviewPanel({
  spec,
  params,
  count = 5,
  cefHeaderOverrides,
  cefExtensionOverrides,
}: PreviewPanelProps) {
  const [samples, setSamples] = useState<string[]>([]);
  const [stamp, setStamp] = useState<number>(0);

  const mut = useMutation({
    mutationFn: () =>
      api.preview({
        ...spec,
        count,
        params,
        cef_header_overrides:
          cefHeaderOverrides && Object.keys(cefHeaderOverrides).length > 0
            ? cefHeaderOverrides
            : undefined,
        cef_extension_overrides:
          cefExtensionOverrides &&
          Object.keys(cefExtensionOverrides).length > 0
            ? cefExtensionOverrides
            : undefined,
      }),
    onSuccess: (data) => {
      setSamples(data.samples);
      setStamp(Date.now());
    },
  });

  // Auto-refresh preview when inputs change — debounced 500ms so typing
  // in the mapping editor doesn't flood the API.
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const paramsKey = JSON.stringify(params);
  const headerKey = JSON.stringify(cefHeaderOverrides ?? {});
  const extKey = JSON.stringify(cefExtensionOverrides ?? {});
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      mut.mutate();
    }, 500);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paramsKey, headerKey, extKey]);

  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-line)] rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-[var(--color-line)] bg-[var(--color-surface-2)]/40">
        <div className="flex items-center gap-2">
          <span className="live-dot" />
          <span className="text-[11px] uppercase tracking-[0.2em] font-mono text-[var(--color-fg-muted)]">
            即時預覽 · {count} 筆樣本
          </span>
        </div>
        <button
          onClick={() => mut.mutate()}
          disabled={mut.isPending}
          className="text-[11px] uppercase tracking-wider font-mono text-[var(--color-accent)] hover:text-[var(--color-fg)] transition-colors disabled:opacity-50"
        >
          {mut.isPending ? "↻ 產生中" : "↻ 重新產生"}
        </button>
      </div>
      <div className="mono p-4 overflow-x-auto whitespace-pre text-[var(--color-fg-muted)] max-h-[420px] overflow-y-auto">
        {mut.isError ? (
          <div className="text-[var(--color-err)]">
            預覽失敗:{(mut.error as Error).message}
          </div>
        ) : samples.length === 0 ? (
          <div className="text-[var(--color-fg-faint)]">…</div>
        ) : (
          samples.map((s, i) => (
            <div
              key={`${stamp}-${i}`}
              className="py-1 border-b border-[var(--color-line)]/40 last:border-0"
            >
              <span className="text-[var(--color-fg-faint)] mr-3 select-none">
                {String(i + 1).padStart(2, "0")}
              </span>
              <span className="text-[var(--color-fg)]">{s}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
