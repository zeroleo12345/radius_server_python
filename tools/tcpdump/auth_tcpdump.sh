set -o verbose
# 指定网卡:     -i eth0
# 指定源ip:     'port 1812 and src 172.16.60.119'
tcpdump -v -i any 'port 1812' -w 1812.pcapng
