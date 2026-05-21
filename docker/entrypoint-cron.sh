#!/bin/sh
set -eu

APP_HOME="${APP_HOME:-/app/mikrotik_audit}"
CRON_SCHEDULE="${CRON_SCHEDULE:-0 */6 * * *}"
SERVICE_ACTION="${SERVICE_ACTION:-audit}"
CRON_FILE="/etc/cron.d/mikrotik-audit"

mkdir -p "${APP_HOME}/logs"

cat > "${CRON_FILE}" <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APP_HOME=${APP_HOME}
SERVICE_ACTION=${SERVICE_ACTION}
TZ=${TZ:-UTC}

${CRON_SCHEDULE} root /usr/local/bin/run-cron-job.sh >> /proc/1/fd/1 2>> /proc/1/fd/2
EOF

chmod 0644 "${CRON_FILE}"
crontab "${CRON_FILE}"

echo "Cron schedule installed: ${CRON_SCHEDULE}"
echo "Service action: ${SERVICE_ACTION}"

exec cron -f
