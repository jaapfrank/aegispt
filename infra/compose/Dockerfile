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
        aircrack-ng \
        awscli \
        feroxbuster \
        ffuf \
        gobuster \
        hashcat \
        httpx-toolkit \
        impacket-scripts \
        iw \
        kerbrute \
        metasploit-framework \
        netexec \
        nmap \
        nikto \
        nuclei \
        openjdk-21-jre-headless \
        procps \
        python-is-python3 \
        python3 \
        python3-pip \
        python3-venv \
        responder \
        ssh-audit \
        snmp \
        sqlmap \
        subfinder \
        testssl.sh \
        wireless-tools \
        zaproxy \
    && rm -rf /var/lib/apt/lists/*

RUN if command -v httpx-toolkit >/dev/null 2>&1 && ! command -v httpx >/dev/null 2>&1; then ln -sf "$(command -v httpx-toolkit)" /usr/local/bin/httpx; fi \
    && if command -v impacket-secretsdump >/dev/null 2>&1 && ! command -v secretsdump.py >/dev/null 2>&1; then ln -sf "$(command -v impacket-secretsdump)" /usr/local/bin/secretsdump.py; fi \
    && if command -v impacket-psexec >/dev/null 2>&1 && ! command -v psexec.py >/dev/null 2>&1; then ln -sf "$(command -v impacket-psexec)" /usr/local/bin/psexec.py; fi \
    && if command -v impacket-wmiexec >/dev/null 2>&1 && ! command -v wmiexec.py >/dev/null 2>&1; then ln -sf "$(command -v impacket-wmiexec)" /usr/local/bin/wmiexec.py; fi \
    && if command -v impacket-GetUserSPNs >/dev/null 2>&1 && ! command -v GetUserSPNs.py >/dev/null 2>&1; then ln -sf "$(command -v impacket-GetUserSPNs)" /usr/local/bin/GetUserSPNs.py; fi \
    && if command -v impacket-GetNPUsers >/dev/null 2>&1 && ! command -v GetNPUsers.py >/dev/null 2>&1; then ln -sf "$(command -v impacket-GetNPUsers)" /usr/local/bin/GetNPUsers.py; fi

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
