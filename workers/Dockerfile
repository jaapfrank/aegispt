FROM golang:1.24-bookworm AS nuclei-builder

ARG NUCLEI_VERSION=v3.6.2

RUN GOBIN=/usr/local/bin go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
    && /usr/local/bin/nuclei -version

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

COPY requirements/base.txt /tmp/requirements-base.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /tmp/requirements-base.txt \
    && pip install --no-cache-dir "semgrep>=1.70,<2.0"

COPY --from=nuclei-builder /usr/local/bin/nuclei /usr/local/bin/nuclei

COPY api /app/api
COPY workers /app/workers

CMD ["dramatiq", "workers.orchestration.tasks"]
