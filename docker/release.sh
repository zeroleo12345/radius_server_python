#!/usr/bin/env sh

export DEBUG=False; export RESTART_POLICY=unless-stopped; docker-compose up -d auth
export DEBUG=False; export RESTART_POLICY=unless-stopped; docker-compose up -d acct
export DEBUG=False; export RESTART_POLICY=unless-stopped; docker-compose up -d dae
