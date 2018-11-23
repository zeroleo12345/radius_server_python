#!/usr/bin/env sh
project_root=$(cd "$(dirname "$0")/.."; pwd)    # /root/radius_server

opkg install python3-cryptography
pip3 install -r $project_root/requirements/requirements.txt

export PYTHONPATH=$project_root/src:$PYTHONPATH
export DICTIONARY_DIR=$project_root/dictionary
export SECRET="testing123"
export USER_DB=$project_root/data/users.db
export API_URL="https://api.lynatgz.cn"
export LOG_DIR="/data/log"
export LOG_LEVEL="debug"
export SENTRY_DSN="https://ac4b7391f0064dc39714b6dc94017214@sentry.io/1325869"
