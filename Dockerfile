FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/app/mikrotik_audit \
    CRON_SCHEDULE="0 */6 * * *" \
    SERVICE_ACTION=audit \
    TZ=UTC

RUN apt-get update \
    && apt-get install -y --no-install-recommends cron iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY mikrotik_audit/reqqurements.txt /tmp/requirements.txt

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r /tmp/requirements.txt

COPY mikrotik_audit/ /app/mikrotik_audit/
COPY docker/entrypoint-cron.sh /usr/local/bin/entrypoint-cron.sh
COPY docker/run-cron-job.sh /usr/local/bin/run-cron-job.sh

RUN chmod +x /usr/local/bin/entrypoint-cron.sh /usr/local/bin/run-cron-job.sh \
    && mkdir -p /app/mikrotik_audit/logs

ENTRYPOINT ["/usr/local/bin/entrypoint-cron.sh"]
