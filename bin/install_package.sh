#!/usr/bin/env sh

pip3 install -r /root/radius_server/requirements/requirements.txt

pip2 install git+https://gitee.com/zeroleo12345/supervisor-3.3.2.git  

mkdir -p /log/supervisord
