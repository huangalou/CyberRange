"""Request / response Pydantic models for the API."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SpecID(BaseModel):
    vendor: str
    product: str
    version: str
    log_type: str


class CatalogEntry(BaseModel):
    vendor: str
    product: str
    version: str
    log_type: str
    description: Optional[str] = None
    format: str
    transport: list[str] = Field(default_factory=list)


class FieldDescriptor(BaseModel):
    name: str
    type: str
    extras: dict[str, Any] = Field(default_factory=dict)


# ─── v4 CEF customizable mapping (mirror engine schema) ───


class CefHeaderModel(BaseModel):
    """Serializable view of engine.schema.CefHeader for API responses."""

    device_vendor: Optional[str] = None
    device_product: Optional[str] = None
    device_version: Optional[str] = None
    signature_id: Optional[str] = None
    name: Optional[str] = None
    severity: Optional[int] = None


class CefMappingEntryModel(BaseModel):
    pa_field: str
    cef_key: str


class CefHeaderOverride(BaseModel):
    """Per-dispatch override for CEF v0 header (any subset of fields)."""

    device_vendor: Optional[str] = None
    device_product: Optional[str] = None
    device_version: Optional[str] = None
    signature_id: Optional[str] = None
    name: Optional[str] = None
    severity: Optional[int] = None


class CefExtensionOverride(BaseModel):
    """Per-dispatch override for one CEF extension entry (key + value)."""

    cef_key: Optional[str] = None
    value: Optional[str] = None


class CatalogDetail(CatalogEntry):
    params: dict[str, Any] = Field(default_factory=dict)
    fields: list[FieldDescriptor] = Field(default_factory=list)
    template: str
    # v4 — only populated when the catalog declares them
    cef_header: Optional[CefHeaderModel] = None
    cef_mapping: Optional[list[CefMappingEntryModel]] = None


class PreviewRequest(SpecID):
    count: int = 5
    params: dict[str, Any] = Field(default_factory=dict)
    # v4 — both default empty/None; engine ignores when catalog has no
    # cef_mapping/cef_header. Per-dispatch ephemeral, no persistence.
    cef_header_overrides: Optional[CefHeaderOverride] = None
    cef_extension_overrides: dict[str, CefExtensionOverride] = Field(
        default_factory=dict
    )


class PreviewResponse(BaseModel):
    samples: list[str]


class BurstSpec(BaseModel):
    """N 筆 / window_s 秒,共 repeat 組,組間隔 gap_s 秒。"""

    # inf 會讓 emit() 的 sleep 拋 OverflowError;在邊界就回 422
    model_config = ConfigDict(allow_inf_nan=False)

    size: int = Field(ge=1)
    window_s: float = Field(gt=0)
    repeat: int = Field(default=1, ge=1)
    gap_s: float = Field(default=0.0, ge=0)

    @property
    def total(self) -> int:
        return self.size * self.repeat


class GenerateRequest(SpecID):
    count: int = 100
    rate: float = 0.0
    params: dict[str, Any] = Field(default_factory=dict)
    sink: str = "stdout://"
    # v4 — same shape as PreviewRequest
    cef_header_overrides: Optional[CefHeaderOverride] = None
    cef_extension_overrides: dict[str, CefExtensionOverride] = Field(
        default_factory=dict
    )
    # 時間模型軸第 1 期:設定時忽略 count,總數 = size * repeat
    burst: Optional[BurstSpec] = None

    @model_validator(mode="after")
    def _burst_excludes_rate(self) -> "GenerateRequest":
        if self.burst is not None and self.rate > 0:
            raise ValueError("burst and rate are mutually exclusive")
        return self

    @property
    def total_count(self) -> int:
        return self.burst.total if self.burst is not None else self.count


class JobStatus(BaseModel):
    id: str
    spec: SpecID
    count: int
    rate: float
    sink: str
    burst: Optional[BurstSpec] = None
    status: str               # pending | running | completed | failed
    sent: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
