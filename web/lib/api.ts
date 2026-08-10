// Typed client for the cyberrange-api FastAPI backend.
//
// 預設走相對路徑 `/api/*`,由外部 reverse proxy(the reverse proxy in front
// of the API)代理到 FastAPI。本機 dev 可用 NEXT_PUBLIC_API_BASE 覆寫成
// `http://127.0.0.1:8001` 直連。
const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "/api";

export type CatalogEntry = {
  vendor: string;
  product: string;
  version: string;
  log_type: string;
  description: string | null;
  format: string;
  transport: string[];
};

export type FieldDescriptor = {
  name: string;
  type: string;
  extras: Record<string, unknown>;
};

// ──────────────── v4 CEF customizable mapping ────────────────

export type CefHeader = {
  device_vendor: string | null;
  device_product: string | null;
  device_version: string | null;
  signature_id: string | null;
  name: string | null;
  severity: number | null;
};

export type CefMappingEntry = {
  pa_field: string;
  cef_key: string;
};

// Per-dispatch override — every field optional. Empty/unset object means
// "no override" (backend treats null === default).
export type CefHeaderOverride = Partial<CefHeader>;

export type CefExtensionOverride = {
  cef_key?: string;
  value?: string;
};

// Keyed by pa_field; each entry may override `cef_key`, `value`, or both.
export type CefExtensionOverrideMap = Record<string, CefExtensionOverride>;

export type CatalogDetail = CatalogEntry & {
  params: Record<string, unknown>;
  fields: FieldDescriptor[];
  template: string;
  cef_header: CefHeader | null;
  cef_mapping: CefMappingEntry[] | null;
};

export type SpecID = {
  vendor: string;
  product: string;
  version: string;
  log_type: string;
};

export type JobStatus = {
  id: string;
  spec: SpecID;
  count: number;
  rate: number;
  sink: string;
  status: "pending" | "running" | "completed" | "failed";
  sent: number;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
};

export type GenerateRequest = SpecID & {
  count: number;
  rate?: number;
  params?: Record<string, unknown>;
  sink: string;
  // v4 — both optional. omit / undefined → backend uses catalog defaults.
  cef_header_overrides?: CefHeaderOverride;
  cef_extension_overrides?: CefExtensionOverrideMap;
};

export type PreviewRequest = SpecID & {
  count: number;
  params?: Record<string, unknown>;
  cef_header_overrides?: CefHeaderOverride;
  cef_extension_overrides?: CefExtensionOverrideMap;
};

// ──────────────── VulnOps reverse-lookup ────────────────

export type VulnOpsQuery = {
  cve?: string[];
  advisory?: string[];
  package?: string[];
  campaign?: string[];
};

export type VulnOpsMatch = {
  path: string;
  log_type: string;
  vendor: string;
  product: string;
  version: string;
  advisory_id: string | null;
  related_campaign: string | null;
  regression_critical: boolean;
  matched_by: string[];
};

export type VulnOpsSummary = {
  catalog_count: number;
  p0_count: number;
  by_advisory: Record<string, number>;
  by_campaign: Record<string, number>;
  by_vendor_product: Record<string, number>;
};

export type VulnOpsQueryResponse = {
  summary: VulnOpsSummary;
  matches: VulnOpsMatch[];
};

// ──────────────── Time-to-Catalog metrics ────────────────

export type MetricEntry = {
  path: string;
  advisory_id: string | null;
  related_campaign: string | null;
  ingested_at: string | null;
  first_commit_at: string | null;
  delta_days: number | null;
  regression_critical: boolean;
};

export type MetricsSummaryModel = {
  catalog_count: number;
  measured_count: number;
  median_delta_days: number | null;
  p90_delta_days: number | null;
  max_delta_days: number | null;
  same_day_count: number;
  by_campaign: Record<string, number>;
  p0_count: number;
};

export type MetricsResponse = {
  summary: MetricsSummaryModel;
  catalogs: MetricEntry[];
};

async function http<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init.headers ?? {}),
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${text || path}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  health: () => http<{ status: string; version: string }>("/healthz"),

  // catalog
  listCatalog: (filters?: { vendor?: string; product?: string }) => {
    const q = new URLSearchParams();
    if (filters?.vendor) q.set("vendor", filters.vendor);
    if (filters?.product) q.set("product", filters.product);
    const qs = q.toString();
    return http<CatalogEntry[]>(`/catalog${qs ? `?${qs}` : ""}`);
  },

  getCatalogDetail: (
    vendor: string,
    product: string,
    version: string,
    logType: string,
  ) =>
    http<CatalogDetail>(`/catalog/${vendor}/${product}/${version}/${logType}`),

  preview: (req: PreviewRequest) =>
    http<{ samples: string[] }>("/preview", {
      method: "POST",
      body: JSON.stringify(req),
    }),

  generate: (req: GenerateRequest) =>
    http<JobStatus>("/generate", {
      method: "POST",
      body: JSON.stringify(req),
    }),

  listJobs: () => http<JobStatus[]>("/jobs"),

  getJob: (id: string) => http<JobStatus>(`/jobs/${id}`),

  vulnopsQuery: (q: VulnOpsQuery) => {
    const params = new URLSearchParams();
    for (const v of q.cve ?? []) params.append("cve", v);
    for (const v of q.advisory ?? []) params.append("advisory", v);
    for (const v of q.package ?? []) params.append("package", v);
    for (const v of q.campaign ?? []) params.append("campaign", v);
    const qs = params.toString();
    return http<VulnOpsQueryResponse>(`/vulnops/query${qs ? `?${qs}` : ""}`);
  },

  ctiMetrics: () => http<MetricsResponse>("/cti/metrics"),
};

export { API_BASE };
