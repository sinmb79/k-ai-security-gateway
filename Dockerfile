FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src
ENV KAI_SECURITY_DB_PATH=/app/data/evidence.sqlite3

RUN pip install --no-cache-dir fastapi uvicorn

COPY pyproject.toml ./
COPY src ./src
COPY apps ./apps

RUN mkdir -p /app/data

EXPOSE 8765

CMD ["python", "-m", "uvicorn", "apps.gateway_api.main:app", "--host", "0.0.0.0", "--port", "8765"]
