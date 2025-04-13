#!/usr/bin/env sh

export ENTRYPOINT="/app/bin/auth.sh"; docker-compose up -d auth
export ENTRYPOINT="/app/bin/acct"; docker-compose up -d acct
export ENTRYPOINT="/app/bin/dae"; docker-compose up -d dae
