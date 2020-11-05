#!/usr/bin/env sh

cd $(dirname "$0")/
project_root=$(pwd)     # /root/radius_server
echo "当前工作目录: $project_root"

export LOG_HEADER="monitor"
source $project_root/.env
exec python3 $project_root/src/processor/process_monitor.py
