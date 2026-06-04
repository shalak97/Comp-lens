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

# Alembic migrations (needed to run `alembic upgrade head` on startup)
COPY alembic ./alembic
COPY alembic.ini .

# Non-root user
RUN useradd -m appuser && chown -R appuser /app
USER appuser

EXPOSE 8000

# Run migrations first, then start the server.
# `alembic upgrade head` is idempotent — safe to run on every deploy.
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
