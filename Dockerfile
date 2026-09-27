FROM python:3.12-slim-bookworm

# Install system deps for Playwright Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdrm2 libdbus-1-3 libxkbcommon0 libatspi2.0-0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 libwayland-client0 \
    fonts-liberation fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
COPY pyproject.toml ./
RUN pip install --no-cache-dir \
    httpx[http2] pydantic pydantic-settings "ruamel.yaml>=0.18" \
    typer structlog orjson rich tabulate grpcio protobuf \
    email-validator tqdm jinja2 playwright anyio lxml pyyaml \
    scikit-learn numpy openpyxl croniter \
    && playwright install chromium --with-deps

# Copy source
COPY src/ ./src/
COPY testcases/ ./testcases/
COPY config.yaml ./
COPY full_scan.py ./
COPY harvest_cookies.py ./
COPY generate_3d_report.py ./
COPY mitre_cache.json ./

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Create reports dir
RUN mkdir -p /app/reports

ENTRYPOINT ["python", "-m", "gotestwaf"]
