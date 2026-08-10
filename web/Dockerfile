# syntax=docker/dockerfile:1.7
# CyberRange Web (Next.js 15 standalone) container.
# Build context = repo root.

FROM node:20-alpine AS deps
WORKDIR /app
COPY web/package.json web/package-lock.json* ./
RUN npm ci

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY web/ ./

# NEXT_PUBLIC_* must be present at build time — they're inlined into client
# bundles. Default to same-origin /api so deployments behind a single vhost
# (reverse proxy → /api/* → cyberrange-api) work without rebuilding.
ARG NEXT_PUBLIC_API_BASE=/api
ENV NEXT_PUBLIC_API_BASE=${NEXT_PUBLIC_API_BASE}
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
RUN addgroup -g 1001 -S nodejs \
 && adduser -S -u 1001 -G nodejs nextjs

ENV NODE_ENV=production \
    HOSTNAME=0.0.0.0 \
    PORT=3000

# Next standalone output bundles its own minimal node_modules + server.js.
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1:3000/ || exit 1

CMD ["node", "server.js"]
