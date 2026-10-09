# syntax=docker/dockerfile:1
# Container image of the remote server (`universal-email-mcp serve`).
#
#   podman build -t universal-email-mcp .
#   podman run --rm -p 8080:8080 -e UEM_DEV_TOKEN=... -e PUBLIC_URL=http://localhost:8080 \
#       -v ./config.local.toml:/config/config.toml:ro -e UEM_CONFIG=/config/config.toml \
#       universal-email-mcp
#
# Build argument EXTRAS adds optional dependency groups, e.g. --build-arg EXTRAS=gcp.

FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.18 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
ARG EXTRAS=""
# Dependencies first: this layer only changes with uv.lock / pyproject.toml.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project $(for e in $EXTRAS; do printf -- '--extra %s ' "$e"; done)
COPY README.md LICENSE NOTICE ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable $(for e in $EXTRAS; do printf -- '--extra %s ' "$e"; done)

FROM python:3.12-slim
RUN useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin uem
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080
USER 10001:10001
EXPOSE 8080
# /health needs no dependencies and no Host header match.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os,sys,urllib.request as u; sys.exit(0 if u.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT','8080'), timeout=2).status == 200 else 1)"]
ENTRYPOINT ["universal-email-mcp"]
CMD ["serve"]
