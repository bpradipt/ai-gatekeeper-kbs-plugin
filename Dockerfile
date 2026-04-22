# ── builder ──────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY ai_gatekeeper/ ai_gatekeeper/
COPY main.py .

RUN python -m venv /venv \
    && /venv/bin/pip install --no-cache-dir .

# ── runtime ──────────────────────────────────────────────────────────────────
FROM python:3.12-slim

COPY --from=builder /venv /venv
COPY --from=builder /app/main.py /app/main.py
COPY --from=builder /app/ai_gatekeeper /app/ai_gatekeeper

WORKDIR /app
RUN useradd -u 1000 -m plugin \
    && chown -R plugin:plugin /app /venv
USER plugin

ENV AI_GATEKEEPER_CONFIG=/etc/ai-gatekeeper/config.yaml
ENTRYPOINT ["/venv/bin/python", "main.py"]
