# syntax=docker/dockerfile:1.7
FROM ghcr.io/astral-sh/uv:0.12.3@sha256:2d890623d310b57771ce840f0da5eed5fc6d657da05ffaa45d82797b53fa3abc AS uv
FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3 AS builder
COPY --from=uv /uv /uvx /bin/
RUN printf '%s\n' \
        'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260803T000000Z bookworm main' \
        'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260803T000000Z bookworm-updates main' \
        'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20260803T000000Z bookworm-security main' \
        > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install --yes --no-install-recommends git=1:2.39.5-0+deb12u3 \
    && rm -rf /var/lib/apt/lists/*
ARG PERSISTENCE_REPOSITORY
ARG PERSISTENCE_REVISION
RUN test -n "$PERSISTENCE_REPOSITORY" \
    && test "${#PERSISTENCE_REVISION}" -eq 40 \
    && git clone --filter=blob:none --no-checkout "$PERSISTENCE_REPOSITORY" /src/persistence \
    && git -C /src/persistence fetch --depth=1 origin "$PERSISTENCE_REVISION" \
    && git -C /src/persistence checkout --detach FETCH_HEAD \
    && test "$(git -C /src/persistence rev-parse HEAD)" = "$PERSISTENCE_REVISION"
ENV UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PYTHONDONTWRITEBYTECODE=1
WORKDIR /src/persistence
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-editable --no-dev

FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3
RUN printf '%s\n' \
        'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260803T000000Z bookworm main' \
        'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260803T000000Z bookworm-updates main' \
        'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20260803T000000Z bookworm-security main' \
        > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install --yes --no-install-recommends gpg=2.2.40-1.1+deb12u2 gpg-agent=2.2.40-1.1+deb12u2 gpgv=2.2.40-1.1+deb12u2 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 kairos \
    && useradd --uid 65532 --gid kairos --no-create-home --shell /usr/sbin/nologin kairos
ENV PATH=/app/.venv/bin:${PATH} PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
COPY --from=builder /src/persistence/.venv /app/.venv
WORKDIR /app
COPY runner.py offline_outbox_reconciliation.py
COPY source-lock.json trusted-signer.asc ./
USER 65532:65532
ENTRYPOINT ["python", "/app/offline_outbox_reconciliation.py"]
CMD ["--mode", "inspect", "--expectation", "/run/secrets/offline_outbox_expectation", "--database-url-file", "/run/secrets/offline_outbox_database_url"]
