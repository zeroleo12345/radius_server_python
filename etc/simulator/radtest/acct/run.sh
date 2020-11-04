### 计费
``` bash
# 运行 Radius Server
sh bin/acct.sh  # python3 src/acct/processor.py

# 发送计费报文
radclient -d ./dictionary 127.0.0.1:1813  acct  'testing123'  < i.txt
```
