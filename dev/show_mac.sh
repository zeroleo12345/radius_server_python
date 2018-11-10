#!/usr/bin/env sh

cat acct*.tmp | awk -F'Alive' '{print $2}' | sort | uniq
