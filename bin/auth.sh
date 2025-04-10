#!/usr/bin/env sh

cd $(dirname "$0")/..
project_root=$(pwd)
echo "当前项目目录: $project_root"

export PYTHONPATH=$project_root/src:$PYTHONPATH

pip freeze | sort
exec python3 $project_root/src/processor/auth_processor.py
