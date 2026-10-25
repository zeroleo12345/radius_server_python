#!/usr/bin/env sh
set -eu 
: "${RADIUS_SERVER_HOST:?RADIUS_SERVER_HOST is required}"
: "${RADIUS_SECRET:?RADIUS_SECRET is required}"

sed \
    -e "s|\${RADIUS_SERVER_HOST}|${RADIUS_SERVER_HOST}|g" \
    -e "s|\${RADIUS_SECRET}|${RADIUS_SECRET}|g" \
    /etc/proxy.conf.template > /etc/proxy.conf
cat /etc/proxy.conf

exec radsecproxy -f -c /etc/proxy.conf
