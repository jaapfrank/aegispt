FROM kalilinux/kali-rolling AS runtime

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PATH="/opt/aegispt/venv/bin:/usr/share/metasploit-framework/bin:${PATH}"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        bloodhound.py \
        ca-certificates \
        curl \
        git \
        hashcat \
        impacket-scripts \
        metasploit-framework \
        netexec \
        nmap \
        nuclei \
        openjdk-21-jre-headless \
        procps \
        python-is-python3 \
        python3 \
        python3-pip \
        python3-venv \
        responder \
        zaproxy \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/base.txt /tmp/requirements-base.txt
RUN python3 -m venv /opt/aegispt/venv \
    && /opt/aegispt/venv/bin/python -m pip install --no-cache-dir --upgrade pip \
    && /opt/aegispt/venv/bin/python -m pip install --no-cache-dir -r /tmp/requirements-base.txt \
    && /opt/aegispt/venv/bin/python -m pip install --no-cache-dir "semgrep>=1.70,<2.0"

COPY api /app/api
COPY workers /app/workers
COPY migrations /app/migrations
COPY ui /app/ui
COPY alembic.ini /app/alembic.ini

CMD ["uvicorn", "api.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
