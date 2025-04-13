#!/usr/bin/env sh

export RESTART_POLICY=no; ENTRYPOINT="tail -f /dev/null" docker-compose up auth