### 安装
``` bash
# MacOS
brew install freeradius-server

关注工具: radtest, radclient
```

### 模拟器radclient 
- 用法 (建议使用)
`radclient [options] server[:port] <command> [<secret>]`


### 模拟器 radclient
- 用法 (不建议使用)
`radtest  user passwd  adius-server[:port] nas-port-number secret`
> radtest  test  test  192.168.1.97  0  testing123
