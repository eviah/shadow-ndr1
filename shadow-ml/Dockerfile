# ---- Stage 1: builder ----
FROM python:3.11-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

# ---- Stage 2: runtime ----
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONPATH=/app \
    SHADOW_LOG_DIR=/app/logs

RUN apt-get update && apt-get install -y --no-install-recommends \
      libpq5 curl passwd \
    && rm -rf /var/lib/apt/lists/* \
    && (getent group shadow || groupadd -g 1500 shadow) \
    && (getent passwd shadow || useradd -u 1500 -g shadow -d /app -s /sbin/nologin shadow) \
    && mkdir -p /app/logs /app/models \
    && chown -R shadow:shadow /app

COPY --from=builder /install /usr/local
WORKDIR /app
COPY --chown=shadow:shadow . /app

USER shadow
EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8001/health || exit 1

CMD ["python", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", "--port", "8001", \
     "--workers", "1", "--timeout-keep-alive", "5", \
     "--limit-concurrency", "100", "--limit-max-requests", "10000", \
     "--access-log", "--no-use-colors"]
