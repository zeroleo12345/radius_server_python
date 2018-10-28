#!/usr/bin/env sh
project_root=$(cd "$(dirname "$0")/.."; pwd)    # /root/radius_server

opkg install python3-cryptography
pip3 install -r $project_root/requirements/requirements.txt

export PYTHONPATH=$project_root/src:$PYTHONPATH
export DICTIONARY_DIR=$project_root/dictionary
export SECRET="testing123"
export USER_DB=$project_root/data/users.db
export API_URL="http://api.lynatgz.cn"
export LOG_DIR="/data/log"
export LOG_LEVEL="debug"
