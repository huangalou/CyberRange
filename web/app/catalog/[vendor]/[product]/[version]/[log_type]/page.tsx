"use client";

import Link from "next/link";
import { use, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  api,
  type CefExtensionOverrideMap,
  type CefHeaderOverride,
} from "@/lib/api";
import { vendorToken, vendorVar } from "@/lib/vendors";
import { CefMappingEditor } from "@/components/cef-mapping-editor";
import { FormatChip } from "@/components/format-chip";
import { ParamForm, parseParams } from "@/components/param-form";
import { PreviewPanel } from "@/components/preview-panel";
import { SendForm } from "@/components/send-form";

type Params = Promise<{
  vendor: string;
  product: string;
  version: string;
  log_type: string;
}>;

export default function SpecDetailPage({ params }: { params: Params }) {
  const { vendor, product, version, log_type } = use(params);

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["catalog", vendor, product, version, log_type],
    queryFn: () =>
      api.getCatalogDetail(vendor, product, version, log_type),
  });

  const [paramRaw, setParamRaw] = useState<Record<string, string>>({});
  // v4 — CEF customizable mapping per-dispatch state. Empty objects when
  // no overrides; preview + dispatch read these directly.
  const [cefHeaderOverrides, setCefHeaderOverrides] =
    useState<CefHeaderOverride>({});
  const [cefExtensionOverrides, setCefExtensionOverrides] =
    useState<CefExtensionOverrideMap>({});

  const parsedParams = useMemo(() => {
    if (!data) return {};
    return parseParams(paramRaw, data.params);
  }, [paramRaw, data]);

  const hasCefEditor = !!data?.cef_mapping && data.cef_mapping.length > 0;

  if (isLoading) {
    return (
      <div className="text-[var(--color-fg-faint)] font-mono text-sm">
        規格載入中…
      </div>
    );
  }
  if (isError || !data) {
    return (
      <div className="border border-[var(--color-err)]/50 bg-[var(--color-err)]/10 rounded-lg p-6 text-sm text-[var(--color-err)]">
        規格載入失敗:{(error as Error)?.message ?? "未知錯誤"}
      </div>
    );
  }

  const t = vendorToken(vendor);

  return (
    <div className="space-y-8">
      <div className="space-y-3">
        <Link
          href="/"
          className="text-[11px] uppercase tracking-[0.2em] font-mono text-[var(--color-fg-faint)] hover:text-[var(--color-fg-muted)] inline-block"
        >
          ← 返回 Log 目錄
        </Link>
        <header
          className="rounded-lg overflow-hidden border border-[var(--color-line)] bg-[var(--color-surface)] flex"
          style={vendorVar(vendor)}
        >
          <div className="vendor-rail w-1.5 shrink-0" />
          <div className="flex-1 p-5 md:p-6 flex flex-col md:flex-row md:items-start md:justify-between gap-4 md:gap-6 min-w-0">
            <div className="space-y-2 min-w-0">
              <div className="text-[10px] uppercase tracking-[0.22em] font-mono vendor-text">
                {t.label} · {product} · v{version}
              </div>
              <h1
                className="font-mono font-medium tracking-tight break-all"
                style={{ fontSize: "var(--text-h1)" }}
              >
                {log_type}
              </h1>
              {data.description ? (
                <p className="text-[13px] leading-relaxed text-[var(--color-fg-muted)] whitespace-pre-line max-w-3xl">
                  {data.description}
                </p>
              ) : null}
            </div>
            <div className="flex flex-row md:flex-col flex-wrap gap-2 md:items-end shrink-0">
              <FormatChip format={data.format} />
              <div className="flex flex-wrap gap-1.5">
                {data.transport.map((tr) => (
                  <span
                    key={tr}
                    className="text-[10px] font-mono text-[var(--color-fg-faint)] border border-[var(--color-line)] rounded px-1.5 py-0.5"
                  >
                    {tr}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </header>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,360px)_minmax(0,1fr)] gap-6">
        <div className="space-y-6">
          <section className="bg-[var(--color-surface)] border border-[var(--color-line)] rounded-lg p-5 space-y-4">
            <div className="text-[11px] uppercase tracking-[0.22em] font-mono text-[var(--color-accent-2)]">
              產生參數
            </div>
            <p className="text-[11px] text-[var(--color-fg-faint)] leading-relaxed">
              依公司測試環境調整來源 IP 池、目的位置、裝置名等;留空代表沿用 catalog 預設值。
            </p>
            <ParamForm defaults={data.params} onChange={setParamRaw} />
          </section>

          <SendForm
            spec={{ vendor, product, version, log_type }}
            params={parsedParams}
            cefHeaderOverrides={hasCefEditor ? cefHeaderOverrides : undefined}
            cefExtensionOverrides={
              hasCefEditor ? cefExtensionOverrides : undefined
            }
          />
        </div>

        <div className="space-y-6 min-w-0">
          {hasCefEditor && data.cef_header && data.cef_mapping ? (
            <CefMappingEditor
              header={data.cef_header}
              mapping={data.cef_mapping}
              headerOverrides={cefHeaderOverrides}
              extensionOverrides={cefExtensionOverrides}
              onHeaderChange={setCefHeaderOverrides}
              onExtensionChange={setCefExtensionOverrides}
            />
          ) : null}

          <PreviewPanel
            spec={{ vendor, product, version, log_type }}
            params={parsedParams}
            count={5}
            cefHeaderOverrides={hasCefEditor ? cefHeaderOverrides : undefined}
            cefExtensionOverrides={
              hasCefEditor ? cefExtensionOverrides : undefined
            }
          />

          <section className="bg-[var(--color-surface)] border border-[var(--color-line)] rounded-lg overflow-hidden">
            <div className="px-4 py-2.5 border-b border-[var(--color-line)] bg-[var(--color-surface-2)]/40 flex items-center justify-between">
              <div className="text-[11px] uppercase tracking-[0.2em] font-mono text-[var(--color-fg-muted)]">
                欄位 schema ({data.fields.length})
              </div>
            </div>
            <div className="divide-y divide-[var(--color-line)]/60 max-h-[360px] overflow-y-auto">
              {data.fields.map((f) => (
                <div
                  key={f.name}
                  className="px-4 py-2 flex items-center gap-4 text-[12px] mono"
                >
                  <span className="text-[var(--color-fg)] w-44 truncate">
                    {f.name}
                  </span>
                  <span className="text-[var(--color-accent-2)] w-32 truncate">
                    {f.type}
                  </span>
                  <span className="text-[var(--color-fg-muted)] truncate flex-1">
                    {Object.entries(f.extras)
                      .map(([k, v]) =>
                        `${k}=${
                          typeof v === "string"
                            ? v
                            : JSON.stringify(v)
                        }`,
                      )
                      .join("  ")}
                  </span>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
