# Mindful Money - Cloud Run deployment
FROM python:3.12-slim

# Security: run as non-root
RUN useradd --create-home --shell /bin/bash appuser
WORKDIR /home/appuser/app

# Install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# Copy application code
COPY --chown=appuser:appuser app.py db.py models.py zkp_verifier.py ./
COPY --chown=appuser:appuser app.js ./static/app.js
COPY --chown=appuser:appuser simplefin-client.js ./static/simplefin-client.js
COPY --chown=appuser:appuser static/ ./static/
COPY --chown=appuser:appuser migrations/ ./migrations/
COPY --chown=appuser:appuser alembic.ini ./

# Cloud Run sets PORT env var; gunicorn listens on it
# Single worker is fine for this workload; increase if needed
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app

USER appuser
