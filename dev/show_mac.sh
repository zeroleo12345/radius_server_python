#!/usr/bin/env sh

cat acct*.tmp | grep IN | awk -F'Alive|Start' '{print $2}' | sort | uniq
