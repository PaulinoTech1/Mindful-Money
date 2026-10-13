# Mindful Money - Cloud Run deployment
# Pinned by multi-arch index digest (resolved 2026-10-13 from registry-1.docker.io).
# The tag is kept for readability; Docker uses the digest. Dependabot (docker
# ecosystem) proposes digest bumps weekly.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

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

# Cloud Run sets PORT env var; gunicorn listens on it.
# Bounded worker timeout: a hung request is killed and logged by gunicorn
# instead of holding a thread forever. deploy.yml sets no --timeout, so Cloud
# Run uses its 300s default; 60s is deliberately tighter (no legitimate route
# needs more; honeypot tarpits cap at 12s). If you raise the Cloud Run request
# timeout or add a slow route, revisit this. graceful 30s for SIGTERM drain.
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 60 --graceful-timeout 30 app:app

USER appuser
