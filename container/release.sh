#!/usr/bin/env sh

export DEBUG=False; export RESTART_POLICY=unless-stopped; ENTRYPOINT="" docker-compose up --no-recreate -d auth
export DEBUG=False; export RESTART_POLICY=unless-stopped; ENTRYPOINT="" docker-compose up --no-recreate -d acct
export DEBUG=False; export RESTART_POLICY=unless-stopped; ENTRYPOINT="" docker-compose up --no-recreate -d dae
