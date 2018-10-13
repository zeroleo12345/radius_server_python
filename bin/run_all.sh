#!/usr/bin/env sh

project_root=$(cd "$(dirname "$0")/.."; pwd)

pip3 install -r $project_root/requirements/requirements.txt

source $project_root/.envrc && python3 $project_root/src/auth.py
