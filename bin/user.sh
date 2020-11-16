#!/usr/bin/env sh

cd $(dirname "$0")/..
project_root=$(pwd)     # /root/radius_server
echo "当前项目目录: $project_root"

export LOG_HEADER="user"
source $project_root/.env
exec python3 $project_root/src/processor/manage_user.py
