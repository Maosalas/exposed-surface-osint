# ── OSINT Tools Container ─────────────────────────────────────────────────────
# Instala herramientas CLI OSINT de forma robusta y verificada.
# Solo accesible dentro de osint-internal — sin exposición externa.

FROM python:3.11-slim

LABEL description="OSINT CLI tools service - internal only"

# ── 1. Sistema base ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git ca-certificates tar \
    dnsutils whois bind9-dnsutils \
    dnsenum \
    nmap \
    ruby ruby-dev \
    perl \
    build-essential libssl-dev libffi-dev python3-dev \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Go 1.22 desde tarball oficial (apt da versión vieja ~1.19) ─────────────
ENV GO_VERSION=1.22.4
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    | tar -C /usr/local -xzf - \
    && echo "Go $(go version)" || true

ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin"
ENV GOPATH=/root/go

# ── 3. Go tools (projectdiscovery) ───────────────────────────────────────────
# Cada uno en su propio RUN para que falle de forma aislada y use caché de Docker
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && echo "✔ subfinder $(subfinder --version 2>&1)" \
    || echo "✖ subfinder install failed (non-fatal)"

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && echo "✔ httpx" \
    || echo "✖ httpx install failed (non-fatal)"

RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && echo "✔ dnsx" \
    || echo "✖ dnsx install failed (non-fatal)"

# amass v4 — usa @latest en vez de @master (más estable)
RUN go install -v github.com/owasp-amass/amass/v4/...@latest \
    && echo "✔ amass" \
    || echo "✖ amass install failed (non-fatal)"

# ── 4. WhatWeb (Ruby gem) ─────────────────────────────────────────────────────
RUN gem install whatweb --no-document \
    && echo "✔ whatweb $(whatweb --version 2>&1 | head -1)" \
    || echo "✖ whatweb install failed (non-fatal)"

# ── 5. theHarvester en virtualenv propio (evita conflictos de deps) ───────────
RUN git clone --depth 1 https://github.com/laramies/theHarvester.git /opt/theHarvester \
    && python3 -m venv /opt/theHarvester-venv \
    && /opt/theHarvester-venv/bin/pip install --no-cache-dir \
         -r /opt/theHarvester/requirements/base.txt \
    && echo "✔ theHarvester" \
    || echo "✖ theHarvester install failed (non-fatal)"

# Wrapper script para theHarvester
RUN echo '#!/bin/sh\n/opt/theHarvester-venv/bin/python3 /opt/theHarvester/theHarvester.py "$@"' \
    > /usr/local/bin/theHarvester \
    && chmod +x /usr/local/bin/theHarvester

# ── 6. wafw00f y dnstwist (pip, sin extras problemáticos) ────────────────────
RUN pip install --no-cache-dir \
    wafw00f \
    dnstwist \
    && echo "✔ wafw00f + dnstwist"

# ── 7. Dependencias Python del servidor ──────────────────────────────────────
COPY requirements-tools.txt /tmp/requirements-tools.txt
RUN pip install --no-cache-dir -r /tmp/requirements-tools.txt \
    && echo "✔ Python requirements"

# ── 8. API server ─────────────────────────────────────────────────────────────
WORKDIR /app
COPY tool_server.py /app/tool_server.py
COPY tools/ /app/tools/

RUN mkdir -p /app/data/tmp

EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD curl -f http://localhost:4000/health || exit 1

CMD ["python3", "-u", "tool_server.py"]
