set -o verbose
sudo tcpdump -v -i any 'port 1813' -w 1813.cap
