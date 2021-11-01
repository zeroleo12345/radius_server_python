#!/usr/bin/env sh

cat acct*.loh | grep OUT | awk -F'|' '{print $4}' | sort | uniq
