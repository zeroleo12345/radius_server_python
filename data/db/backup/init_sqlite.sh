#!/usr/bin/env sh

current_dir=$(cd "$(dirname "$0")"; pwd)

sqlite3 $current_dir/users.db ".read $current_dir/sqlite_insert.sql"
