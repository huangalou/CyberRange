#!/usr/bin/env python3
"""Run tests/fixtures/wazuh-logtest/<set>/ against a live Wazuh manager.

Each fixture dir carries expected.json ({fixtures: [{sample_file,
phase3_must_fire, phase3_min_level, phase3_must_not_fire, phase2_observe}]}).
The sample is piped through `wazuh-logtest` inside the manager container over
ssh; Phase 2 decoder + fields and the Phase 3 rule are parsed back and compared.

    python scripts/wazuh_logtest_fixtures.py sophos-hmpa-prevent symantec-sep-sonar
    python scripts/wazuh_logtest_fixtures.py --all
    WAZUH_SSH=lab@192.0.2.10 WAZUH_DOCKER=/usr/local/bin/docker \
        WAZUH_CONTAINER=<manager-container> python scripts/... --all

Exit code 1 if any fixture fails. Only Phase 3 (rule id / level) is pass-fail;
phase2_observe and the top-level `decoder` name are reported, never enforced.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "wazuh-logtest"
SSH = os.environ.get("WAZUH_SSH", "lab@192.0.2.10")          # RFC 5737 doc address — override
DOCKER = os.environ.get("WAZUH_DOCKER", "docker")
CONTAINER = os.environ.get("WAZUH_CONTAINER", "wazuh-manager")

RX_KV = re.compile(r"^\t(\S+?): '(.*)'$")


def logtest(sample: Path) -> dict:
    cmd = ["ssh", SSH, f"{DOCKER} exec -i {CONTAINER} /var/ossec/bin/wazuh-logtest"]
    out = subprocess.run(cmd, input=sample.read_bytes(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60).stdout.decode("utf-8", "replace")
    phase, res = None, {"decoder": None, "fields": {}, "rule": None, "level": None, "description": None, "raw": out}
    for line in out.splitlines():
        if line.startswith("**Phase 2"):
            phase = 2
            continue
        if line.startswith("**Phase 3"):
            phase = 3
            continue
        m = RX_KV.match(line)
        if not m:
            continue
        k, v = m.groups()
        if phase == 2:
            if k == "name":
                res["decoder"] = v
            else:
                res["fields"][k] = v
        elif phase == 3:
            if k == "id":
                res["rule"] = int(v)
            elif k == "level":
                res["level"] = int(v)
            elif k == "description":
                res["description"] = v
    return res


def run_set(name: str, verbose: bool) -> tuple[int, int]:
    d = FIXTURES / name
    spec = json.loads((d / "expected.json").read_text())
    ok = fail = 0
    if "fixtures" not in spec:
        print(f"### {name}  — expected.json has no `fixtures` list (legacy layout), skipped")
        return 0, 0
    print(f"### {name}  (expects decoder {spec.get('decoder')})")
    for fx in spec["fixtures"]:
        r = logtest(d / fx["sample_file"])
        problems = []
        must = fx.get("phase3_must_fire", [])
        if must and r["rule"] not in must:
            problems.append(f"fired {r['rule']} want one of {must}")
        if r["rule"] in fx.get("phase3_must_not_fire", []):
            problems.append(f"fired forbidden {r['rule']}")
        if fx.get("phase3_min_level") is not None and (r["level"] or 0) < fx["phase3_min_level"]:
            problems.append(f"level {r['level']} < {fx['phase3_min_level']}")
        notes = []
        if spec.get("decoder") and r["decoder"] != spec["decoder"]:
            notes.append(f"decoder {r['decoder']!r} != expected {spec['decoder']!r} (observe only)")
        observed = {k: v for k, v in fx.get("phase2_observe", {}).items() if not k.startswith("_")}
        missed = {k: (r["fields"].get(k), v) for k, v in observed.items() if r["fields"].get(k) != v}
        mark = "PASS" if not problems else "FAIL"
        ok += not problems
        fail += bool(problems)
        print(f"  {mark} {fx['name']:<28} rule={r['rule']} lvl={r['level']} dec={r['decoder']} :: {r['description']}")
        for p in problems:
            print(f"       ! {p}")
        for n in notes:
            print(f"       ~ {n}")
        if missed:
            print(f"       ~ phase2_observe (bonus) not matched: {missed}")
        if verbose:
            print(r["raw"])
    return ok, fail


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sets", nargs="*")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    names = sorted(p.name for p in FIXTURES.iterdir() if (p / "expected.json").exists()) if a.all else a.sets
    if not names:
        ap.error("give fixture set names or --all")
    tot_ok = tot_fail = 0
    for n in names:
        o, f = run_set(n, a.verbose)
        tot_ok += o
        tot_fail += f
    print(f"\n{tot_ok} passed, {tot_fail} failed")
    return 1 if tot_fail else 0


if __name__ == "__main__":
    sys.exit(main())
