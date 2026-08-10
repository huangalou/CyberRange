// Vendor identity tokens — color + short label, used for cards/badges.
export type VendorToken = {
  label: string;
  hue: string;       // CSS oklch hue value used in --vendor-h
  category: "ngfw" | "endpoint" | "network" | "web" | "linux";
};

export const VENDORS: Record<string, VendorToken> = {
  fortinet:  { label: "Fortinet",   hue: "20",   category: "ngfw" },
  paloalto:  { label: "Palo Alto",  hue: "40",   category: "ngfw" },
  cisco:     { label: "Cisco",      hue: "230",  category: "network" },
  microsoft: { label: "Microsoft",  hue: "200",  category: "endpoint" },
  linux:     { label: "Linux",      hue: "85",   category: "linux" },
  apache:    { label: "Apache",     hue: "150",  category: "web" },
};

export function vendorToken(vendor: string): VendorToken {
  return (
    VENDORS[vendor] ?? {
      label: vendor,
      hue: "260",
      category: "network",
    }
  );
}

export function vendorVar(vendor: string): React.CSSProperties {
  // Inject --vendor-h so card styles can use oklch(... var(--vendor-h)).
  return { ["--vendor-h" as string]: vendorToken(vendor).hue };
}
