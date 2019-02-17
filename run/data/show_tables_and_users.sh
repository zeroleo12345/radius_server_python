echo '[table:]'
sqlite3 users.db '.tables'

echo ''
echo '[users:]'
sqlite3 users.db 'select * from user;'
