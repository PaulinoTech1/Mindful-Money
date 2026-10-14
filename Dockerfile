# Mindful Money - Cloud Run deployment
# Pinned by multi-arch index digest (resolved 2026-10-13 from registry-1.docker.io).
# The tag is kept for readability; Docker uses the digest. Dependabot (docker
# ecosystem) proposes digest bumps weekly.
# ---- ZK verifier runtime (build stage) ----
# Fetches bb 5.1.0 and a truncated BN254 CRS over HTTPS, every file pinned by
# sha256, and checks the committed v4 VK against the committed circuit. See
# scripts/fetch_zkp_runtime.py and docs/ZKP_BINDING.md "Availability".
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS zkp-runtime
COPY zkp/manual_expense_v4/target/manual_expense_v4.json zkp/manual_expense_v4/target/vk zkp/manual_expense_v4/target/vk_hash /build/v4/
COPY scripts/fetch_zkp_runtime.py /build/
RUN python /build/fetch_zkp_runtime.py /opt/zkp /build/v4

FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

# Build args for version tracking (set by CI)
ARG GITHUB_SHA=unknown
ARG BUILD_TIMESTAMP=unknown
ENV GITHUB_SHA=${GITHUB_SHA}
ENV BUILD_TIMESTAMP=${BUILD_TIMESTAMP}

# Security: run as non-root
RUN useradd --create-home --shell /bin/bash appuser
WORKDIR /home/appuser/app

# Install dependencies first (better layer caching)
COPY requirements-hashed.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements-hashed.txt

# Copy application code
COPY --chown=appuser:appuser app.py db.py models.py zkp_verifier.py alembic.ini ./
COPY --chown=appuser:appuser static/ ./static/
COPY --chown=appuser:appuser migrations/ ./migrations/
COPY --chown=appuser:appuser geoip/ ./geoip/

# ZK verifier: bb binary, baked CRS (no request-time download) and the v4
# VK. Root-owned and read-only for appuser. About 40 MB (bb is 38 MB).
COPY --from=zkp-runtime /opt/zkp/bb /usr/local/bin/bb
COPY --from=zkp-runtime /opt/zkp/crs/ /opt/zkp/crs/
COPY --from=zkp-runtime /opt/zkp/vk /opt/zkp/v4/vk
ENV ZKP_BB_EXECUTABLE=/usr/local/bin/bb \
    ZKP_CRS_DIR=/opt/zkp/crs \
    ZKP_V4_VK_PATH=/opt/zkp/v4/vk

# Cloud Run sets PORT env var; gunicorn listens on it.
# Bounded worker timeout: a hung request is killed and logged by gunicorn
# instead of holding a thread forever. deploy.yml sets no --timeout, so Cloud
# Run uses its 300s default; 60s is deliberately tighter (no legitimate route
# needs more; honeypot tarpits cap at 12s). If you raise the Cloud Run request
# timeout or add a slow route, revisit this. graceful 30s for SIGTERM drain.
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 60 --graceful-timeout 30 app:app

USER appuser
