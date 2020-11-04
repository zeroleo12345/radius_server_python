###  鉴权
```
# 运行 Radius Server
sh bin/auth.sh  # python3 src/auth/processor.py

# 鉴权报文
radclient 127.0.0.1:1812  auth  'testing123'  < chap.txt
```
