# cyberrange-web

Next.js 15 (App Router) frontend for the CyberRange catalog generator.

## Stack

- Next.js 15 + React 19 (App Router, server + client components)
- TanStack Query for server-state caching + polling
- Tailwind CSS v4 (CSS `@theme` tokens, no JS config)
- TypeScript strict mode

## Pages

| Route | Purpose |
|---|---|
| `/` | Catalog grid: filter, vendor-coloured cards, click to open spec |
| `/catalog/[vendor]/[product]/[version]/[log_type]` | Spec detail, parameter form, live preview, dispatch form |
| `/jobs` | Dispatched job list, polled every 1.5 s |

## Run

```bash
# Backend first
cd ../api && source ../engine/.venv/bin/activate && cyberrange-api

# Frontend (separate shell)
cd web
npm install         # one-off
npm run dev         # http://localhost:3000
```

API base is read from `NEXT_PUBLIC_API_BASE`, default `http://127.0.0.1:8001`.

## Build

```bash
npm run typecheck
npm run build
```

Bundle (gzipped, after build):
- `/`               ~116 kB First Load JS
- `/catalog/...`    ~119 kB
- `/jobs`           ~112 kB

All within the landing-page budget (<150 kB).

## Design notes

- Dark navy (`oklch(13% 0.025 250)`) base, acid-lime accent (`oklch(86% 0.22 130)`)
- Vendor identity hue tokens in `lib/vendors.ts` drive card rails and badges via `--vendor-h`
- Mono font (`ui-monospace`) for log samples and identifiers; sans-serif for prose
- Subtle dot-grid background for atmosphere; no decorative gradients

## TODO (Phase 3+ polish)

- Server-side prefetch for `/catalog` so initial HTML carries data (no flash of skeleton)
- Persist last-used params in localStorage per spec
- Real-time job tail (websocket) instead of 1.5 s poll
- Dual-send toggle (Wazuh + ELK) on dispatch form
