# syntax=docker/dockerfile:1

# Build Stage ==================================================================
FROM python:3.12-slim-bookworm AS build

RUN pip install --no-cache-dir uv

WORKDIR /app

COPY pyproject.toml ./
RUN uv pip install --system --no-cache .

COPY . .
RUN uv pip install --system --no-cache .


# Main Stage ===================================================================
FROM python:3.12-slim-bookworm

# Prepare environment
RUN <<EOF
    set -e

    # Install dependencies for Playwright/Chromium
    apt-get update && apt-get install -y --no-install-recommends \
        tini \
        chromium \
        fonts-inter \
        fontconfig \
        && rm -rf /var/lib/apt/lists/*

    fc-cache -fv

    # Add non-root user
    groupadd gtw
    useradd -g gtw -m gtw

    # Create app directory
    mkdir -p /app/reports
    chown -R gtw:gtw /app
EOF

WORKDIR /app

COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin/gotestwaf /usr/local/bin/gotestwaf
COPY ./testcases ./testcases
COPY ./config.yaml ./

USER gtw

VOLUME [ "/app/reports" ]

ENTRYPOINT [ "/usr/bin/tini", "--", "gotestwaf" ]
