import type { ReactNode } from "react";

export function PageHeader({
  eyebrow,
  title,
  subtitle,
  actions,
}: {
  eyebrow?: string;
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="flex items-end justify-between gap-6 pb-8 border-b border-[var(--color-line)]">
      <div className="space-y-2">
        {eyebrow ? (
          <div className="text-[11px] uppercase tracking-[0.22em] text-[var(--color-accent-2)] font-mono">
            {eyebrow}
          </div>
        ) : null}
        <h1
          className="font-semibold tracking-tight leading-[1.05]"
          style={{ fontSize: "var(--text-h1)" }}
        >
          {title}
        </h1>
        {subtitle ? (
          <p className="text-[var(--color-fg-muted)] max-w-2xl text-sm leading-relaxed">
            {subtitle}
          </p>
        ) : null}
      </div>
      {actions ? <div className="flex gap-3 shrink-0">{actions}</div> : null}
    </header>
  );
}
