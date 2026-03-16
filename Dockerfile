# OSINT Surface Analyzer - Docker Image
# OSINT Surface Analyzer

FROM python:3.11-slim

LABEL maintainer="OSINT Analyzer"
LABEL description="OSINT exposed attack surface analyzer"

# ──────────────────────────────────────────────────────────────
# 1. System dependencies + OSINT tools
# ──────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    curl wget git dnsutils whois nmap \
    # Build tools
    build-essential python3-dev \
    # Network tools
    dnsutils iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based tools
RUN apt-get update && apt-get install -y golang-go --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Install subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || \
    echo "subfinder install skipped"

ENV PATH="$PATH:/root/go/bin"

# Install dnstwist
RUN pip install dnstwist --no-cache-dir 2>/dev/null || echo "dnstwist install via apt fallback" && \
    apt-get update && apt-get install -y python3-dnstwist --no-install-recommends 2>/dev/null || true && \
    rm -rf /var/lib/apt/lists/*

# Install theHarvester
RUN pip install theHarvester --no-cache-dir 2>/dev/null || echo "theHarvester skipped"

# ──────────────────────────────────────────────────────────────
# 2. Application setup
# ──────────────────────────────────────────────────────────────
WORKDIR /app

# Copy and install Python backend
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY backend/ /app/

# Copy frontend
COPY frontend/ /app/frontend/

# Create output directory for frontend dist (serve index.html directly)
RUN mkdir -p /app/frontend/dist && mkdir -p /app/data/scans && cp /app/frontend/index.html /app/frontend/dist/index.html

# ──────────────────────────────────────────────────────────────
# 3. Runtime
# ──────────────────────────────────────────────────────────────
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
