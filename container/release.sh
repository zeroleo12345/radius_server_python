#!/usr/bin/env sh

export RESTART_POLICY=unless-stopped; ENTRYPOINT="" docker-compose up -d auth
export RESTART_POLICY=unless-stopped; ENTRYPOINT="" docker-compose up -d acct
export RESTART_POLICY=unless-stopped; ENTRYPOINT="" docker-compose up -d dae
