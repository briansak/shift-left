FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/shift-left-shared ./shift-left-shared
COPY services/orchestrator/pyproject.toml .
COPY services/orchestrator/shift_left ./shift_left
COPY reference-seed ./reference-seed

RUN pip install --no-cache-dir ./shift-left-shared && pip install --no-cache-dir . \
    && rm -rf /usr/local/lib/python3.12/site-packages/shift_left \
    && python -c "from importlib.resources import files; ui=files('shift_left')/'ui'; assert (ui/'static'/'styles.css').is_file() and (ui/'templates'/'base.html').is_file(), ui"

ENV SHIFT_LEFT_CONFIG=/config/shift-left.yaml
EXPOSE 8080

CMD ["shift-left-orchestrator"]
