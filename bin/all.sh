#!/usr/bin/env sh

project_root=$(cd "$(dirname "$0")/.."; pwd)    # /root/radius_server

supervisord -c $project_root/etc/supervisord.ini

