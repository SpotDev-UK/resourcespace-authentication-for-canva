FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml requirements.lock ./
COPY src ./src
COPY LICENSE README.md ./

RUN pip install --upgrade pip && \
    pip install --no-deps -r requirements.lock && \
    pip install --no-deps .

RUN useradd --system --uid 1001 --no-create-home --gid 0 broker && \
    mkdir -p /var/lib/resourcespace-platform && \
    chown -R broker:0 /var/lib/resourcespace-platform

ENV PORT=3001 \
    STORAGE_PATH=/var/lib/resourcespace-platform/platform-store.json

EXPOSE 3001
USER broker

CMD ["python", "-m", "resourcespace_platform.main"]
