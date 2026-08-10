import { vendorToken, vendorVar } from "@/lib/vendors";

export function VendorBadge({ vendor }: { vendor: string }) {
  const t = vendorToken(vendor);
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] uppercase tracking-wider font-mono vendor-soft-bg vendor-text border vendor-border"
      style={vendorVar(vendor)}
    >
      <span
        className="w-1 h-1 rounded-full"
        style={{ background: `oklch(75% 0.18 ${t.hue})` }}
      />
      {t.label}
    </span>
  );
}
