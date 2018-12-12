#!/usr/bin/env sh

project_root=$(cd "$(dirname "$0")/.."; pwd)    # /root/radius_server

export LOG_HEADER="auth"
source $project_root/.env
exec python3 $project_root/src/auth/processor.py
