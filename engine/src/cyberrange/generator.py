"""Field-level generators + Jinja2 template rendering."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import random
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from jinja2 import Template

from .schema import CatalogSpec, CefHeader, CefMappingEntry, FieldSpec

_log = logging.getLogger(__name__)


PARAM_PREFIX = "${params."


def _resolve_param_ref(value: Any, params: dict[str, Any]) -> Any:
    """If value is `${params.X}` string, return params[X]; else return as-is."""
    if isinstance(value, str) and value.startswith(PARAM_PREFIX) and value.endswith("}"):
        key = value[len(PARAM_PREFIX) : -1]
        return params[key]
    return value


def _render_datetime(fmt: str) -> str:
    now = datetime.now(timezone.utc)
    if fmt == "epoch":
        return str(int(now.timestamp()))
    if fmt == "epoch_ns":
        return str(int(now.timestamp() * 1_000_000_000))
    return now.strftime(fmt)


def _render_faker(method: str) -> str:
    if method == "uuid4":
        return str(uuid.uuid4()).upper()
    if method == "md5":
        return hashlib.md5(secrets.token_bytes(16)).hexdigest().upper()
    if method == "sha256":
        return hashlib.sha256(secrets.token_bytes(32)).hexdigest().upper()
    if method == "sha1":
        return hashlib.sha1(secrets.token_bytes(20)).hexdigest().upper()
    if method == "hex_8":
        return secrets.token_hex(4).upper()
    if method == "hex_16":
        return secrets.token_hex(8).upper()
    raise ValueError(f"unknown faker method: {method!r}")


def _render_field(fs: FieldSpec, params: dict[str, Any], prior: dict[str, str]) -> str:
    extras = fs.model_dump(exclude={"name", "type"})
    t = fs.type

    if t == "fixed":
        return str(extras["value"])

    if t == "param":
        return str(params[extras["param"]])

    if t == "choice":
        choices = _resolve_param_ref(extras["choices"], params)
        return str(random.choice(list(choices)))

    if t == "weighted_choice":
        choices = _resolve_param_ref(extras["choices"], params)
        keys = list(choices.keys())
        weights = [float(v) for v in choices.values()]
        return str(random.choices(keys, weights=weights, k=1)[0])

    if t == "int_range":
        return str(random.randint(int(extras["min"]), int(extras["max"])))

    if t == "cidr":
        cidr = _resolve_param_ref(extras["cidr"], params)
        net = ipaddress.ip_network(cidr, strict=False)
        size = net.num_addresses
        # avoid network and broadcast for IPv4 /<31
        if isinstance(net, ipaddress.IPv4Network) and size > 2:
            idx = random.randint(1, size - 2)
        else:
            idx = random.randint(0, max(0, size - 1))
        return str(net.network_address + idx)

    if t == "datetime":
        return _render_datetime(extras["format"])

    if t == "template":
        ctx = {**params, **prior, "params": params}
        return Template(extras["template"]).render(**ctx)

    if t == "faker":
        return _render_faker(extras["method"])

    raise ValueError(f"unknown field type: {t!r} for field {fs.name!r}")


def _cef_escape(v: Any) -> str:
    """Escape a CEF extension VALUE per the CEF v0 spec.

    Inside the extensions body (k=v k=v ...), the special chars are:
      `\\`  →  `\\\\`
      `=`   →  `\\=`
      `\\n` →  `\\\\n`

    Pipes `|` are NOT special in extensions (only in the header section).
    """
    s = str(v)
    s = s.replace("\\", "\\\\")
    s = s.replace("=", "\\=")
    s = s.replace("\n", "\\n")
    return s


def _compose_cef_extensions(
    mapping: list[CefMappingEntry],
    rendered: dict[str, str],
    overrides: dict[str, dict[str, Any]],
) -> str:
    """Walk `cef_mapping` and render the CEF extensions body.

    Resolution per entry (priority highest → lowest):
      1. overrides[pa_field].value      — pin literal value
      2. rendered[pa_field]              — value produced by the field generator
      (none) → entry skipped, with a warning

    `cef_key` resolution:
      1. overrides[pa_field].cef_key    — remap to a different CEF key
      2. entry.cef_key                  — YAML default (PA admin guide)

    Ad-hoc extensions:
      Any override targeting a pa_field NOT in `mapping` is appended to the
      end of the body — but only if it carries BOTH cef_key and value
      (otherwise we don't know where to land it or what to render).
    """
    pairs: list[str] = []
    seen: set[str] = set()
    for entry in mapping:
        seen.add(entry.pa_field)
        ov = overrides.get(entry.pa_field, {}) or {}
        key = ov.get("cef_key") or entry.cef_key
        if "value" in ov and ov["value"] is not None:
            val = ov["value"]
        elif entry.pa_field in rendered:
            val = rendered[entry.pa_field]
        else:
            _log.warning(
                "cef_mapping entry %r has no generator and no value override; "
                "skipping",
                entry.pa_field,
            )
            continue
        pairs.append(f"{key}={_cef_escape(val)}")

    for extra_field, ov in overrides.items():
        if extra_field in seen:
            continue
        ov = ov or {}
        key = ov.get("cef_key")
        val = ov.get("value")
        if key is None or val is None:
            _log.warning(
                "ad-hoc cef extension override %r needs BOTH cef_key and value; "
                "got %r — skipping",
                extra_field,
                ov,
            )
            continue
        pairs.append(f"{key}={_cef_escape(val)}")

    return " ".join(pairs)


def _resolve_cef_header(
    header: CefHeader,
    overrides: dict[str, Any],
) -> dict[str, Any]:
    """Return a plain dict of CEF header fields with overrides applied.

    Jinja receives this as `cef_header.<field>` (dict attribute access).
    None values stay None so the template can decide what to do with them.
    """
    resolved = header.model_dump()
    for k, v in (overrides or {}).items():
        if v is not None:
            resolved[k] = v
    return resolved


def render_one(
    spec: CatalogSpec,
    params: dict[str, Any] | None = None,
    cef_header_overrides: dict[str, Any] | None = None,
    cef_extension_overrides: dict[str, dict[str, Any]] | None = None,
) -> str:
    merged = {**spec.default_params(), **(params or {})}
    rendered: dict[str, str] = {}
    for fs in spec.fields:
        rendered[fs.name] = _render_field(fs, merged, rendered)

    ctx: dict[str, Any] = {**rendered, "params": merged}

    # v4 CEF customizable mapping — only kicks in when the catalog declares it.
    # Older catalogs (no cef_mapping / no cef_header) hit zero extra code.
    if spec.cef_mapping is not None:
        ctx["cef_extensions"] = _compose_cef_extensions(
            spec.cef_mapping, rendered, cef_extension_overrides or {}
        )
    if spec.cef_header is not None:
        ctx["cef_header"] = _resolve_cef_header(
            spec.cef_header, cef_header_overrides or {}
        )

    return Template(spec.template).render(**ctx)


def render_many(
    spec: CatalogSpec,
    count: int,
    params: dict[str, Any] | None = None,
    cef_header_overrides: dict[str, Any] | None = None,
    cef_extension_overrides: dict[str, dict[str, Any]] | None = None,
) -> Iterator[str]:
    for _ in range(count):
        yield render_one(
            spec,
            params,
            cef_header_overrides=cef_header_overrides,
            cef_extension_overrides=cef_extension_overrides,
        )
