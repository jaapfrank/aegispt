FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

COPY requirements/base.txt /tmp/requirements-base.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /tmp/requirements-base.txt

COPY api /app/api
COPY workers /app/workers
COPY migrations /app/migrations
COPY alembic.ini /app/alembic.ini

CMD ["uvicorn", "api.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
