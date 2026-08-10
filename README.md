# CyberRange — A DetectOps Harness

**Vendor-accurate log generation → SIEM ingestion → detection validation, as a repeatable engineering loop.**

CyberRange is a detection-engineering harness built around a simple idea: SOC teams should be able to *prove* their detections work — continuously, against realistic telemetry, with measurable KPIs — instead of assuming rules fire because they parsed once.

Point it at a vendor/product/version, and it generates log streams that are faithful to the real format (FortiGate key-value, PAN-OS CSV/CEF, Windows Sysmon XML, CloudTrail JSON, ModSecurity audit JSON, …), ships them to your SIEM sinks (Wazuh, Elastic, file, syslog), and verifies that the expected detection rules actually fire.

```
┌──────────┐    ┌──────────┐    ┌───────────────┐    ┌──────────────────┐
│ catalog/ │ →  │ engine/  │ →  │ sinks         │ →  │ verify           │
│ 53 YAML  │    │ generate │    │ Wazuh / ELK   │    │ rule fired?      │
│ specs    │    │ + chain  │    │ syslog / file │    │ Time-to-Detect?  │
└──────────┘    └──────────┘    └───────────────┘    └──────────────────┘
```

## Why "DetectOps"

VulnOps manages the vulnerability lifecycle; DetectOps manages the **detection lifecycle** — from threat intel to catalog spec to deployed rule to *verified* detection, with regression on every change. CyberRange operationalizes three KPIs:

| KPI | Question it answers |
|---|---|
| **Time-to-Catalog** | How fast does a new advisory become a generatable, testable log spec? |
| **Time-to-Detect** | Once traffic flows, how fast does the rule fire? |
| **Time-to-Verified-Detection** | How fast from "rule written" to "proven firing against realistic samples"? |

## What's inside

- **`catalog/`** — 53 YAML log-format specs across 23 vendor/product lines (Fortinet, Palo Alto, Cisco ASA/Firepower, F5 ASM, Citrix NetScaler, Imperva, Microsoft Windows/Sysmon, Linux auditd/OpenSSH, Kubernetes audit, AWS CloudTrail, OWASP ModSecurity CRS, Trend Micro, Symantec, Sophos, McAfee, Kaspersky, F-Secure, Nginx, Apache, …). Schema v4: field generators (pool/faker/weighted), OCSF mapping, CEF header/extension mapping, `cti.iocs` and `vulnops.cve_refs` blocks.
- **`engine/`** — Python library + `cyberrange` CLI. Template-driven generation with realistic field distributions, rate control, time-window replay, multi-sink dispatch. 199 tests.
- **`api/` + `web/`** — FastAPI backend + Next.js UI: browse the catalog, preview samples, dispatch jobs, track history, reverse-lookup CVE → catalog → detection rule (`/vulnops`), CTI metrics dashboard (`/metrics`). 47 API tests.
- **`runbooks/`** — end-to-end validation runbooks for real campaigns, e.g. a FortiGate SSL-VPN exploitation **S3→S4 pivot detection slice** (auth-success → AD account-creation correlation) and a supply-chain campaign pilot with custom Wazuh rule chains — each with TDD fixtures (`tests/fixtures/wazuh-logtest/*/expected.json`), live-fire dual-shipping (Wazuh + Elastic), and detection-count verification.
- **`cti/` subsystem** — RSS advisory feeds → IoC extraction → catalog draft generation, closing the intel-to-detection loop.

## Design principles

1. **Catalog-first** — log formats are data (YAML specs), not code. Adding a vendor is a spec, not a fork.
2. **Generate, don't attack** — chain/campaign mode replays *telemetry* of multi-stage attacks; it never executes exploits or touches external targets.
3. **TDD for detections** — every rule ships with fixtures and an `expected.json`; regression is a first-class citizen.
4. **Dual-SIEM aware** — single source, dual output (Wazuh + Elastic) to validate both stacks against identical traffic.

## Quick start

```bash
# Engine + API (shared venv)
cd engine && python -m venv .venv && source .venv/bin/activate && pip install -e . -e ../api
cyberrange-api                    # http://127.0.0.1:8001

# Web UI
cd web && npm install && npm run dev   # http://localhost:3000

# Or straight from the CLI
cyberrange gen \
  --vendor fortinet --product fortios --version 7.4 --type traffic \
  --count 1000 --rate 50/s --sink udp://192.0.2.10:514
```

> IPs in docs use RFC 5737 documentation addresses (`192.0.2.x`). Configure your own sinks via `.env` (`CYBERRANGE_ALLOWED_SINK_HOSTS`) — see `.env.example`.

## Status

Active development. Catalog expansion (Azure AD sign-in), SSE job streaming, Triage Discipline regression scheduler, and chain-mode campaign playbooks are on the roadmap — see `CLAUDE.md` for project conventions.

## License

Apache-2.0
