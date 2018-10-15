#!/usr/bin/env sh

project_root=$(cd "$(dirname "$0")/.."; pwd)    # /root/radius_server

source $project_root/bin/base.sh
python3 $project_root/src/auth/processor.py
