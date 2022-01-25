#!/usr/bin/env sh

cat acct*.log | grep IN | awk -F'Alive|Start' '{print $2}' | sort | uniq
