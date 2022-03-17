#!/usr/bin/env sh

current=$(dirname "$0")
$current/stop.sh && $current/release.sh
