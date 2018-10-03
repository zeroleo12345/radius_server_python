
# 启动demon程序
supervisord -c /root/radius_server/etc/supervisord.ini 

# 启动进程
# supervisorctl -c /root/radius_server/etc/supervisord.ini start auth
