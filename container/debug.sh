#!/usr/bin/env sh

ENTRYPOINT="tail -f /dev/null" docker-compose up -d auth
