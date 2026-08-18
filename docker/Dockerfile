# syntax=docker/dockerfile:1.7

FROM ghcr.io/astral-sh/uv:0.12.3@sha256:2d890623d310b57771ce840f0da5eed5fc6d657da05ffaa45d82797b53fa3abc AS uv

FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3 AS builder

COPY --from=uv /uv /uvx /bin/

# Git is build-only: uv.lock references reviewed kairos-core/kairos-llm commits.
# Use the immutable Debian snapshot that produced the pinned Python base image.
RUN printf '%s\n' \
        'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260803T000000Z bookworm main' \
        'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260803T000000Z bookworm-updates main' \
        'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20260803T000000Z bookworm-security main' \
        > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install --yes --no-install-recommends git=1:2.39.5-0+deb12u3 \
    && rm -rf /var/lib/apt/lists/*

ARG PACKAGE_DIR
ARG SERVICE_EXTRA=""
ARG SOURCE_REPOSITORY
ARG SOURCE_REVISION

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# `service` is a named remote Git build context pinned in docker-compose.yml.
# Copy only package metadata and runtime source; tests, local .env files and VCS
# metadata never enter the image context or runtime layer.
# hadolint ignore=DL3022
COPY --from=service pyproject.toml uv.lock README.md ./
# hadolint ignore=DL3022
COPY --from=service ${PACKAGE_DIR}/ ./${PACKAGE_DIR}/

RUN --mount=type=cache,target=/root/.cache/uv \
    if [ -n "${SERVICE_EXTRA}" ]; then \
        uv sync --locked --no-dev --no-editable --extra "${SERVICE_EXTRA}"; \
    else \
        uv sync --locked --no-dev --no-editable; \
    fi

FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3 AS runtime

ARG SOURCE_REPOSITORY
ARG SOURCE_REVISION

LABEL org.opencontainers.image.source="${SOURCE_REPOSITORY}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.vendor="Kairos-cryptoAI"

ENV PATH=/app/.venv/bin:${PATH} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1

RUN groupadd --gid 10001 kairos \
    && useradd --uid 10001 --gid kairos --no-create-home --shell /usr/sbin/nologin kairos

WORKDIR /app
COPY --from=builder --chown=kairos:kairos /app/.venv /app/.venv
COPY --chmod=0555 docker/entrypoint.sh /usr/local/bin/kairos-entrypoint

USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/kairos-entrypoint"]

# Every Compose service overrides this with its installed, lockfile-backed entrypoint.
CMD ["python", "--version"]
