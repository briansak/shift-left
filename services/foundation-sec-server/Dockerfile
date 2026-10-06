FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/shift-left-shared ./shift-left-shared
COPY services/orchestrator ./orchestrator
COPY services/foundation-sec-server/pyproject.toml .
COPY services/foundation-sec-server/foundation_sec_server ./foundation_sec_server

RUN pip install --no-cache-dir ./shift-left-shared \
    && pip install --no-cache-dir ./orchestrator \
    && pip install --no-cache-dir .

ENV ALLOW_NON_LOOPBACK_BIND=true
ENV FOUNDATION_SEC_BIND_HOST=0.0.0.0

EXPOSE 8091
CMD ["foundation-sec-server"]
