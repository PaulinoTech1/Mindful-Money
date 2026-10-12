# Mindful Money - Cloud Run deployment
FROM python:3.12-slim

# Build args for version tracking (set by CI)
ARG GITHUB_SHA=unknown
ARG BUILD_TIMESTAMP=unknown
ENV GITHUB_SHA=${GITHUB_SHA}
ENV BUILD_TIMESTAMP=${BUILD_TIMESTAMP}

# Security: run as non-root
RUN useradd --create-home --shell /bin/bash appuser
WORKDIR /home/appuser/app

# Install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# Copy application code
COPY --chown=appuser:appuser app.py db.py models.py zkp_verifier.py alembic.ini ./
COPY --chown=appuser:appuser static/ ./static/
COPY --chown=appuser:appuser migrations/ ./migrations/
COPY --chown=appuser:appuser geoip/ ./geoip/

# Cloud Run sets PORT env var; gunicorn listens on it
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app

USER appuser
