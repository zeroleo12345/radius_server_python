#!/usr/bin/env sh

project_root=$(cd "$(dirname "$0")/.."; pwd)    # /root/radius_server

export LOG_HEADER="monitor"
source $project_root/.env
exec python3 $project_root/src/processor/process_monitor.py
