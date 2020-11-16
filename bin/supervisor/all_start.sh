#!/usr/bin/env sh

project_root=$(cd "$(dirname "$0")/.."; pwd)    # /root/radius_server

source $project_root/.env
supervisord -c $project_root/etc/supervisord.ini

