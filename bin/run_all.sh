#!/usr/bin/env sh

project_root=$(cd "$(dirname "$0")/.."; pwd)    # /root/radius_server

pip3 install -r $project_root/requirements/requirements.txt

export DICTIONARY_DIR=$project_root/dictionary
export SECRET="testing123"
export PYTHONPATH=$project_root/src:$PYTHONPATH
python3 $project_root/src/auth/auth.py
