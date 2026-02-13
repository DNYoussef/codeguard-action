FROM python:3.11-slim

LABEL maintainer="GuardSpine <support@guardspine.io>"
LABEL org.opencontainers.image.source="https://github.com/DNYoussef/codeguard-action"
LABEL org.opencontainers.image.description="AI-aware code governance with verifiable evidence bundles"

# Install git for diff operations
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /action

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy action code
COPY src/ ./src/
COPY lib/ ./lib/
COPY rubrics/ ./rubrics/
COPY entrypoint.py .
# Decision engine profiles are inside src/decision_profiles/ (copied with src/)

# Set entrypoint
ENTRYPOINT ["python", "/action/entrypoint.py"]
