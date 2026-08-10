# cyberrange-api

FastAPI backend wrapping the `cyberrange` engine. Provides catalog browsing,
synchronous sample preview, and background generation jobs to syslog/file sinks.

## Install (dev, shared venv with engine)

```bash
cd CyberRange/api
source ../engine/.venv/bin/activate     # reuse engine venv
pip install -e '.[dev]'                  # cyberrange already installed editable from engine/
```

Or fresh venv:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ../engine
pip install -e '.[dev]'
```

## Run

```bash
cyberrange-api                           # uvicorn on 127.0.0.1:8001
# or
uvicorn cyberrange_api.main:app --reload --port 8001
```

OpenAPI docs: http://127.0.0.1:8001/docs

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness |
| GET | `/catalog` | List all specs (`?vendor=`, `?product=` filters) |
| GET | `/catalog/{vendor}/{product}/{version}/{log_type}` | Spec detail (params, fields, template) |
| POST | `/preview` | Synchronously render up to 100 samples |
| POST | `/generate` | Kick off background job (returns 202 + job_id) |
| GET | `/jobs` | List jobs |
| GET | `/jobs/{id}` | Single job status |

## Quick demo

```bash
# List
curl localhost:8001/catalog | jq

# Preview 3 Sysmon samples
curl -s localhost:8001/preview \
  -H 'content-type: application/json' \
  -d '{"vendor":"microsoft","product":"windows","version":"2022","log_type":"sysmon.event_id_1","count":3}' \
  | jq '.samples[0]'

# Send 50 Fortinet logs to ELK filebeat (UDP 514 on .18)
curl -s localhost:8001/generate \
  -H 'content-type: application/json' \
  -d '{"vendor":"fortinet","product":"fortios","version":"7.4","log_type":"traffic.forward","count":50,"sink":"udp://192.0.2.18:514"}' \
  | jq
```

## Tests

```bash
pytest
```
