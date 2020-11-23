#!/usr/bin/env sh

# ENTRYPOINT=sh; docker-compose up -d auth

docker-compose up -d auth
docker-compose up -d acct
