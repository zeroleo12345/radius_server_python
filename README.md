### 系统简介
pppoe 用户鉴权计费


### 运行鉴权
``` bash
./bin/run_auth.sh
```


### 运行计费
``` bash
./bin/run_acct.sh
```


### 使用客户端测试服务 (目前项目内固定secret为: testing123)
``` bash
radtest  test  test  192.168.1.97  0  testing123
```

