# syntax=docker/dockerfile:1.7
# CyberRange API container.
# Build context = repo root (so we can copy both engine/ and api/).

FROM python:3.12-slim AS builder

WORKDIR /build
RUN pip install --no-cache-dir --upgrade pip build

COPY engine/ ./engine/
COPY api/    ./api/

RUN python -m build --wheel --outdir /wheels ./engine \
 && python -m build --wheel --outdir /wheels ./api


FROM python:3.12-slim

ARG APP_UID=1000
RUN useradd -u ${APP_UID} -m -s /usr/sbin/nologin app

WORKDIR /app

COPY --from=builder /wheels/ /tmp/wheels/
RUN pip install --no-cache-dir /tmp/wheels/*.whl \
 && rm -rf /tmp/wheels

# Catalog is data, not code — mount or copy at the deploy layer.
COPY --chown=app:app catalog/ /app/catalog/

ENV PYTHONUNBUFFERED=1 \
    CYBERRANGE_CATALOG_DIR=/app/catalog \
    API_HOST=0.0.0.0 \
    API_PORT=8001

EXPOSE 8001
USER app

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8001/healthz', timeout=2).status==200 else 1)"

CMD ["python", "-m", "uvicorn", "cyberrange_api.main:app", \
     "--host", "0.0.0.0", "--port", "8001"]
