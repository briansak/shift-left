# CPU/CUDA inference image. Apple Silicon MPS: run natively on host (see README).
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/shift-left-shared ./shift-left-shared
COPY services/antares-server/pyproject.toml .
COPY services/antares-server/antares_server ./antares_server

RUN pip install --no-cache-dir ./shift-left-shared && pip install --no-cache-dir .

ENV ANTARES_MODEL_PATH=/models/antares
ENV ANTARES_BACKEND=auto
ENV ANTARES_LOAD_STRATEGY=on_demand
ENV ALLOW_NON_LOOPBACK_BIND=true
ENV ANTARES_BIND_HOST=0.0.0.0

EXPOSE 8090

CMD ["antares-server"]
