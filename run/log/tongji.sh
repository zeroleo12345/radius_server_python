#!/usr/bin/env sh

set -o verbose

cat acct_$(date "+%Y%m%d")_* | awk -F'|' '{print $2'} | sort | uniq
 
cat acct_$(date "+%Y%m%d")_* | awk -F'|' '{print $2'} | sort | uniq | wc
