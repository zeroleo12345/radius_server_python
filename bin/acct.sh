#!/usr/bin/env sh

project_root=$(cd "$(dirname "$0")/.."; pwd)    # /root/radius_server

export LOG_HEADER="acct"
source $project_root/bin/env.sh
exec python3 $project_root/src/acct/processor.py
