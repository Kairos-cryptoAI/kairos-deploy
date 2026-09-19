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
ENV UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-editable
# Test fixtures, NOT production package substitutes. Only the exact published
# execution revision is copied; no current working tree enters this image.
RUN git init /tmp/execution-fixtures \
    && git -C /tmp/execution-fixtures remote add origin https://github.com/Kairos-cryptoAI/kairos-execution-engine.git \
    && git -C /tmp/execution-fixtures fetch --depth=1 origin 73122e825b333281d4fd4acce1c57f90c4cc511c \
    && git -C /tmp/execution-fixtures checkout --detach FETCH_HEAD

FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3
ENV PATH=/app/.venv/bin:${PATH} PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/work/execution-fixtures:/work/release_gate
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /tmp/execution-fixtures/tests /work/execution-fixtures/tests
WORKDIR /work/release_gate
COPY policy.py witness.py test_policy.py test_witness.py test_full_path.py test_pipeline.py pyproject.toml compose.yml Dockerfile ./
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--capture=tee-sys", "--tb=short", "test_policy.py", "test_witness.py", "test_full_path.py", "test_pipeline.py"]
