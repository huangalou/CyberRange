"""Request / response Pydantic models for the API."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


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


class JobStatus(BaseModel):
    id: str
    spec: SpecID
    count: int
    rate: float
    sink: str
    status: str               # pending | running | completed | failed
    sent: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
