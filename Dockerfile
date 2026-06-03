FROM python:3.11-slim

# System deps for psycopg + paramiko (cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Non-root user (security best practice)
RUN useradd -m appuser && chown -R appuser /app
USER appuser

EXPOSE 8000

# $PORT is set by most PaaS; default to 8000 locally
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
