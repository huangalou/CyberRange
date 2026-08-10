const FORMAT_LABEL: Record<string, string> = {
  key_value: "KEY=VAL",
  json: "JSON",
  csv: "CSV",
  cisco_mnemonic: "CISCO-MNEMONIC",
  rfc3164: "RFC-3164",
  combined_log: "NCSA-COMBINED",
};

export function FormatChip({ format }: { format: string }) {
  const label = FORMAT_LABEL[format] ?? format.toUpperCase();
  return (
    <span className="inline-flex items-center px-2 py-0.5 text-[10px] uppercase tracking-[0.15em] font-mono border border-[var(--color-line-strong)] text-[var(--color-fg-muted)] rounded">
      {label}
    </span>
  );
}
