#!/usr/bin/env sh

export ENTRYPOINT="/app/bin/auth.sh"; docker-compose up -d auth
export ENTRYPOINT="/app/bin/acct.sh"; docker-compose up -d acct
export ENTRYPOINT="/app/bin/dae.sh"; docker-compose up -d dae
