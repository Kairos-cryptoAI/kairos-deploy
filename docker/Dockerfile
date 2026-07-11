# Generic image for any Kairos Python service.
# Build context is the PARENT directory that contains all kairos-* repos as siblings.
FROM python:3.11-slim AS base

ARG SERVICE_DIR
ARG MODULE
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

WORKDIR /app
# Shared library first (better layer caching).
COPY kairos-core /src/kairos-core
RUN pip install /src/kairos-core
# The LLM gateway is needed by the analytical layers; harmless elsewhere.
# Never mask installation failures: every image must contain the exact same gateway build.
COPY kairos-llm /src/kairos-llm
RUN pip install /src/kairos-llm

COPY ${SERVICE_DIR} /src/${SERVICE_DIR}
RUN pip install /src/${SERVICE_DIR}

ENV KAIROS_MODULE=${MODULE}
CMD ["sh", "-c", "python -m $KAIROS_MODULE"]
