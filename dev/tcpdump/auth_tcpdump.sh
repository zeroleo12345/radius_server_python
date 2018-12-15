set -o verbose
sudo tcpdump -v -i any 'port 1812' -w 1812.cap
