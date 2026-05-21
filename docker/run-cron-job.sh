#!/bin/sh
set -eu

APP_HOME="${APP_HOME:-/app/mikrotik_audit}"
SERVICE_ACTION="${SERVICE_ACTION:-audit}"

cd "${APP_HOME}"
python ./main.py service --once --action "${SERVICE_ACTION}" --no-progress
