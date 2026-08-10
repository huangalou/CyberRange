"""Load and discover catalog YAML specs."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

import yaml

from .schema import CatalogSpec


def _resolve_catalog_root() -> Path:
    env_dir = os.environ.get("CYBERRANGE_CATALOG_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    # Fallback: walk up from src/cyberrange/loader.py to repo root /catalog
    return Path(__file__).resolve().parents[3] / "catalog"


CATALOG_ROOT = _resolve_catalog_root()


def load_spec(path: Path) -> CatalogSpec:
    with Path(path).open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return CatalogSpec.model_validate(data)


def find_spec(
    vendor: str,
    product: str,
    version: str,
    log_type: str,
    root: Path = CATALOG_ROOT,
) -> Path:
    """Locate a spec file by vendor/product/version/log_type.

    Tries:
      1. <root>/<vendor>/<product>/<version>/<log_type>.yaml
      2. <root>/<vendor>/<product>/<version>/<last-segment>.yaml
      3. scan all yaml in that dir, match spec.log_type
    """
    base = Path(root) / vendor / product / version
    direct = base / f"{log_type}.yaml"
    if direct.exists():
        return direct

    last_segment = log_type.rsplit(".", 1)[-1]
    fallback = base / f"{last_segment}.yaml"
    if fallback.exists():
        return fallback

    if base.exists():
        for f in base.glob("*.yaml"):
            spec = load_spec(f)
            if spec.log_type == log_type:
                return f

    raise FileNotFoundError(
        f"No catalog spec for {vendor}/{product}/{version}/{log_type} under {root}"
    )


def list_specs(root: Path = CATALOG_ROOT) -> Iterable[tuple[Path, CatalogSpec]]:
    for p in sorted(Path(root).rglob("*.yaml")):
        try:
            yield p, load_spec(p)
        except Exception as e:
            print(f"[loader] skip invalid spec {p}: {e}")
