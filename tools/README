### 安装
``` bash
brew install freeradius-server

关注工具: radtest, radclient
```

### 冒烟测试
- 启动程序
- 鉴权
``` bash
sh bin/auth.sh  # python3 src/auth/processor.py
```


- 计费
``` bash
sh bin/acct.sh  # python3 src/acct/processor.py
```


### 流程测试
radtest  test  test  192.168.1.97  0  testing123
建议使用: radclient [options] server[:port] <command> [<secret>]

```
# 鉴权报文
radclient 127.0.0.1:1812  auth  'testing123'  < auth/chap.txt

# 计费报文
radclient -d ./dictionary 127.0.0.1:1813  acct  'testing123'  < acct/i.txt
```
