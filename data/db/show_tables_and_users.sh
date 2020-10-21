echo '[显示所有表:]'
sqlite3 users.db '.tables'

echo ''
echo '[users表记录:]'
sqlite3 users.db 'select * from user;'
