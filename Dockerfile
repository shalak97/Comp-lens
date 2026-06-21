FROM python:3.11-slim

# System deps for psycopg + paramiko (cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV PYTHONPATH=/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App source
COPY app ./app

# Alembic migrations (run on startup)
COPY alembic ./alembic
COPY alembic.ini .

# Policy-as-code definitions + CLI (the policy engine needs these at runtime)
COPY policies ./policies
COPY cli ./cli

# Evidence store dir
RUN mkdir -p /data/evidence

# Non-root user
RUN useradd -m appuser && chown -R appuser /app /data
USER appuser

EXPOSE 8000

# Migrations are idempotent — safe to run on every boot. Then start the server.
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
