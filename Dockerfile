FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /action

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Flatten into a single layer ---
FROM python:3.11-slim

LABEL maintainer="GuardSpine <support@guardspine.io>"
LABEL org.opencontainers.image.source="https://github.com/DNYoussef/codeguard-action"
LABEL org.opencontainers.image.description="AI-aware code governance with verifiable evidence bundles"

# Copy git binary and its dependencies from builder
COPY --from=builder /usr/bin/git /usr/bin/git
COPY --from=builder /usr/lib/git-core/ /usr/lib/git-core/
COPY --from=builder /usr/share/git-core/ /usr/share/git-core/
COPY --from=builder /usr/lib/*-linux-gnu/libpcre2-8.so* /usr/lib/*-linux-gnu/

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

WORKDIR /action

# Copy action code
COPY src/ ./src/
COPY lib/pii-shield.wasm ./lib/pii-shield.wasm
COPY rubrics/ ./rubrics/
COPY entrypoint.py .

ENTRYPOINT ["python", "/action/entrypoint.py"]
