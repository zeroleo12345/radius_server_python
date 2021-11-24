#!/usr/bin/env sh

export RESTART_POLICY=unless-stopped; docker-compose up -d auth
export RESTART_POLICY=unless-stopped; docker-compose up -d acct
