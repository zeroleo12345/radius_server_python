#!/usr/env/bin sh

supervisorctl -c /root/radius_server/etc/supervisord.ini restart auth
