#!/usr/bin/env sh

cd $(dirname "$0")/..
project_root=$(pwd)     # /root/radius_server
echo "当前项目目录: $project_root"

export PYTHONPATH=$project_root/src:$PYTHONPATH
# 环境变量
export LOG_HEADER="auth"

if [ -n "$ENTRYPOINT" ]; then
    echo "eval $ENTRYPOINT"
    eval $ENTRYPOINT
else
    exec python3 $project_root/src/processor/auth_processor.py
fi
