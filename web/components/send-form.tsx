"use client";

import { useMutation } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import {
  api,
  type CefExtensionOverrideMap,
  type CefHeaderOverride,
  type SpecID,
} from "@/lib/api";

interface SendFormProps {
  spec: SpecID;
  params: Record<string, unknown>;
  cefHeaderOverrides?: CefHeaderOverride;
  cefExtensionOverrides?: CefExtensionOverrideMap;
}

type SinkKind = "stdout" | "udp" | "tcp" | "file";

const SINK_OPTIONS: { value: SinkKind; label: string; hint: string }[] = [
  { value: "stdout", label: "標準輸出", hint: "輸出到 API 伺服器 stdout,適合快速驗證樣本" },
  { value: "udp", label: "UDP Syslog", hint: "送往指定主機:埠號 (預設 514)" },
  { value: "tcp", label: "TCP Syslog", hint: "送往指定主機:埠號 (預設 1514)" },
  { value: "file", label: "本機檔案", hint: "寫入 API 伺服器檔案 (例如 /tmp/cr.log)" },
];

const DEFAULT_PORT: Record<SinkKind, string> = {
  stdout: "",
  udp: "514",
  tcp: "1514",
  file: "",
};

function buildSinkUri(
  kind: SinkKind,
  host: string,
  port: string,
  filePath: string,
): string {
  switch (kind) {
    case "stdout":
      return "stdout://";
    case "file":
      return `file://${filePath.trim() || "/tmp/cr.log"}`;
    case "udp":
    case "tcp":
      return `${kind}://${host.trim()}:${port.trim()}`;
  }
}

export function SendForm({
  spec,
  params,
  cefHeaderOverrides,
  cefExtensionOverrides,
}: SendFormProps) {
  const router = useRouter();
  const [count, setCount] = useState(100);
  const [rate, setRate] = useState(0);
  const [sinkKind, setSinkKind] = useState<SinkKind>("stdout");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [filePath, setFilePath] = useState("/tmp/cr.log");
  const [msg, setMsg] = useState<string | null>(null);
  const [isError, setIsError] = useState(false);

  const sinkUri = useMemo(
    () => buildSinkUri(sinkKind, host, port, filePath),
    [sinkKind, host, port, filePath],
  );

  const needsHostPort = sinkKind === "udp" || sinkKind === "tcp";
  const canDispatch =
    count >= 1 && (!needsHostPort || (host.trim() !== "" && port.trim() !== ""));

  const mut = useMutation({
    mutationFn: () =>
      api.generate({
        ...spec,
        count,
        rate,
        params,
        sink: sinkUri,
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
    onSuccess: (job) => {
      setIsError(false);
      setMsg(`工作 ${job.id.slice(0, 8)}… 已派送`);
      setTimeout(() => router.push("/jobs"), 600);
    },
    onError: (e) => {
      setIsError(true);
      setMsg(`派送失敗:${(e as Error).message}`);
    },
  });

  function selectSink(next: SinkKind) {
    setSinkKind(next);
    if ((next === "udp" || next === "tcp") && port === "") {
      setPort(DEFAULT_PORT[next]);
    }
  }

  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-line)] rounded-lg p-5 space-y-5">
      <div className="text-[11px] uppercase tracking-[0.22em] font-mono text-[var(--color-accent-2)]">
        派送設定
      </div>

      <div className="grid grid-cols-2 gap-3">
        <label className="block space-y-1.5">
          <span className="text-[11px] uppercase tracking-wider text-[var(--color-fg-muted)] font-mono">
            數量
          </span>
          <input
            type="number"
            min={1}
            value={count}
            onChange={(e) => setCount(parseInt(e.target.value || "0", 10))}
            className="w-full bg-[var(--color-bg)] border border-[var(--color-line)] rounded-md px-3 py-2 mono focus:outline-none focus:border-[var(--color-accent)]"
          />
        </label>
        <label className="block space-y-1.5">
          <span className="text-[11px] uppercase tracking-wider text-[var(--color-fg-muted)] font-mono">
            速率 (筆 / 秒, 0 = 全速)
          </span>
          <input
            type="number"
            min={0}
            step={0.1}
            value={rate}
            onChange={(e) => setRate(parseFloat(e.target.value || "0"))}
            className="w-full bg-[var(--color-bg)] border border-[var(--color-line)] rounded-md px-3 py-2 mono focus:outline-none focus:border-[var(--color-accent)]"
          />
        </label>
      </div>

      <div className="space-y-2.5">
        <span className="text-[11px] uppercase tracking-wider text-[var(--color-fg-muted)] font-mono block">
          目的 Sink
        </span>
        <div className="grid grid-cols-2 gap-2">
          {SINK_OPTIONS.map((opt) => {
            const active = sinkKind === opt.value;
            return (
              <button
                key={opt.value}
                type="button"
                onClick={() => selectSink(opt.value)}
                className={`text-left px-3 py-2 rounded-md border transition-colors ${
                  active
                    ? "border-[var(--color-accent)] bg-[var(--color-accent)]/8"
                    : "border-[var(--color-line)] hover:border-[var(--color-line-strong)]"
                }`}
              >
                <div className="text-[12px] font-medium text-[var(--color-fg)]">
                  {opt.label}
                </div>
                <div className="text-[10.5px] text-[var(--color-fg-faint)] leading-snug mt-0.5">
                  {opt.hint}
                </div>
              </button>
            );
          })}
        </div>

        {needsHostPort ? (
          <div className="grid grid-cols-[1fr_120px] gap-2 pt-1">
            <label className="block space-y-1.5">
              <span className="text-[10px] uppercase tracking-wider text-[var(--color-fg-faint)] font-mono">
                目的主機 / IP
              </span>
              <input
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="例如 192.168.10.20"
                className="w-full bg-[var(--color-bg)] border border-[var(--color-line)] rounded-md px-3 py-2 mono focus:outline-none focus:border-[var(--color-accent)]"
              />
            </label>
            <label className="block space-y-1.5">
              <span className="text-[10px] uppercase tracking-wider text-[var(--color-fg-faint)] font-mono">
                埠號
              </span>
              <input
                value={port}
                onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))}
                inputMode="numeric"
                placeholder={DEFAULT_PORT[sinkKind]}
                className="w-full bg-[var(--color-bg)] border border-[var(--color-line)] rounded-md px-3 py-2 mono focus:outline-none focus:border-[var(--color-accent)]"
              />
            </label>
          </div>
        ) : null}

        {sinkKind === "file" ? (
          <label className="block space-y-1.5 pt-1">
            <span className="text-[10px] uppercase tracking-wider text-[var(--color-fg-faint)] font-mono">
              檔案路徑 (相對於 API 伺服器)
            </span>
            <input
              value={filePath}
              onChange={(e) => setFilePath(e.target.value)}
              placeholder="/tmp/cr.log"
              className="w-full bg-[var(--color-bg)] border border-[var(--color-line)] rounded-md px-3 py-2 mono focus:outline-none focus:border-[var(--color-accent)]"
            />
          </label>
        ) : null}

        <div className="text-[10.5px] font-mono text-[var(--color-fg-faint)] pt-1">
          目的位址 ▸{" "}
          <span className="text-[var(--color-fg-muted)] select-all">
            {sinkUri}
          </span>
        </div>
      </div>

      <button
        onClick={() => {
          setMsg(null);
          setIsError(false);
          mut.mutate();
        }}
        disabled={mut.isPending || !canDispatch}
        className="w-full mt-1 px-4 py-2.5 bg-[var(--color-accent)] text-[var(--color-bg)] font-mono uppercase tracking-[0.18em] text-sm rounded-md hover:bg-[var(--color-accent-2)] active:scale-[0.99] transition disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {mut.isPending ? "派送中…" : "▶ 派送工作"}
      </button>

      {msg ? (
        <div
          className={`text-[12px] mono ${
            isError ? "text-[var(--color-err)]" : "text-[var(--color-ok)]"
          }`}
        >
          {msg}
        </div>
      ) : null}
    </div>
  );
}
