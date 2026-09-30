FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    HOST=0.0.0.0 \
    PORT=5050 \
    NOIR_WORKER_ENABLED=false \
    HOME=/home/harpocrates

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated unprivileged non-root user and group (UID/GID 10001)
RUN groupadd --system --gid 10001 harpocrates \
    && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /home/harpocrates --shell /usr/sbin/nologin harpocrates \
    && mkdir -p /tmp/harpocrates_jobs /app \
    && chown -R harpocrates:harpocrates /tmp/harpocrates_jobs /app /home/harpocrates

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=harpocrates:harpocrates . .

USER harpocrates:harpocrates

EXPOSE 5050

CMD ["gunicorn", "--bind", "0.0.0.0:5050", "--workers", "2", "--threads", "4", "--timeout", "240", "app:app"]

# Liveness probe for standalone `docker run` / orchestrators that honor
# Dockerfile HEALTHCHECK. Uses /health (process alive) rather than /ready
# so a transient dependency blip does not mark the container unhealthy.
# docker-compose.yml continues to probe /ready for service readiness gates.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5050/health', timeout=5)"

