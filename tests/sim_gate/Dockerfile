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
WORKDIR /src/execution
RUN git init . \
    && git remote add origin https://github.com/Kairos-cryptoAI/kairos-execution-engine.git \
    && git fetch --depth=1 origin ec0a817097dbc654336b3308da6092e6db25514b \
    && test "$(git rev-parse FETCH_HEAD)" = ec0a817097dbc654336b3308da6092e6db25514b \
    && git checkout --detach FETCH_HEAD
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --group dev --no-editable

FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3
ENV PATH=/app/.venv/bin:${PATH} PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/work/sim_gate:/work/execution
COPY --from=builder /src/execution/.venv /app/.venv
COPY --from=builder /src/execution/kairos_execution /work/execution/kairos_execution
COPY --from=builder /src/execution/tests/test_simulation_bridge.py /work/execution/tests/test_simulation_bridge.py
COPY --from=builder /src/execution/tests/test_simulation_controller.py /work/execution/tests/test_simulation_controller.py
COPY --from=builder /src/execution/tests/test_simulation_controller_integration.py /work/execution/tests/test_simulation_controller_integration.py
COPY --from=builder /src/execution/tests/test_simulation_fill_model.py /work/execution/tests/test_simulation_fill_model.py
WORKDIR /work/sim_gate
COPY policy.py test_policy.py execution-revision.txt compose.fixture.json pytest.ini Dockerfile ./
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--capture=tee-sys", "--tb=short", "test_policy.py", "/work/execution/tests/test_simulation_bridge.py", "/work/execution/tests/test_simulation_controller.py", "/work/execution/tests/test_simulation_controller_integration.py", "/work/execution/tests/test_simulation_fill_model.py"]
