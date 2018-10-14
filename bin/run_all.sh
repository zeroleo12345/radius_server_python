#!/usr/bin/env sh

project_root=$(cd "$(dirname "$0")/.."; pwd)    # /root/radius_server

pip3 install -r $project_root/requirements/requirements.txt

export PYTHONPATH=$project_root/src:$PYTHONPATH
export DICTIONARY_DIR=$project_root/dictionary
export SECRET="testing123"
export USER_DB=$project_root/data/users.db
python3 $project_root/src/auth/processor.py
