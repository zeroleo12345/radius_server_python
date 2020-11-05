#!/usr/bin/env sh

cd $(dirname "$0")/
project_root=$(pwd)     # /root/radius_server
echo "当前工作目录: $project_root"

export PYTHONPATH=$project_root/src:$PYTHONPATH
# 环境变量
export LOG_HEADER="auth"

exec python3 $project_root/src/processor/auth_processor.py
