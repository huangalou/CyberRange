# TeamPCP Supply Chain Campaign — IOC Excerpt (Test Fixture)

This is a focused excerpt of the Datadog Security Labs advisory used as
fixture for `cti.ioc_extractor`. Real source:
`https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/`

## Executive Summary

A coordinated supply chain campaign designated "TeamPCP" compromised
multiple critical open-source projects. The campaign reached PyPI on
March 24–27 with backdoored releases of `litellm` (versions 1.82.7 and
1.82.8) and `telnyx` (versions 4.87.1 and 4.87.2).

For comparison, see the GitHub Security Lab and PyPA references.

## Indicators of Compromise

### Network Infrastructure

| Indicator | Description | Type |
|-----------|-------------|------|
| `models.litellm[.]cloud` | LiteLLM exfiltration endpoint | Domain |
| `checkmarx[.]zone/raw` | Follow-on C2 polling | Domain |
| `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0[.]io` | CanisterWorm ICP canister | Domain |
| `aquasecurtiy[.]org` | Trivy typosquat C2 | Domain |
| `83.142.209[.]203` | Telnyx second-stage server | IP |
| `83.142.209[.]11` | Related campaign infrastructure | IP |
| `46.151.182[.]203` | Related campaign infrastructure | IP |

The Telnyx payload downloads from `hxxp://83.142.209[.]203:8080/ringtone.wav`.

### Filesystem Persistence

| Path | Description |
|------|-------------|
| `*/litellm_init.pth` | Malicious Python startup hook |
| `*/.config/sysmon/sysmon.py` | LiteLLM persistence script |
| `*/.config/systemd/user/sysmon.service` | User-level systemd unit |
| `/tmp/pglog` | Downloaded second-stage payload |
| `/tmp/.pg_state` | Beacon state file |

### HTTP Fingerprints

| Fingerprint | Description |
|-------------|-------------|
| `X-Filename: tpcp.tar.gz` | LiteLLM exfiltration header |

### Compromised Packages

| Package | Versions | Status |
|---------|----------|--------|
| `litellm` | 1.82.7, 1.82.8 | Confirmed compromised |
| `telnyx` | 4.87.1, 4.87.2 | Confirmed compromised |

## Notes

- All affected packages have been quarantined on PyPI.
- Reference: anchore.com supply-chain advisory database.
