### 系统简介
pppoe 用户鉴权计费


### 安装
``` bash
pip3 install -r requirements/requirements.txt

git clone https://github.com/zeroleo12345/myclog-python.git
python3 setup.py install

git clone https://github.com/zeroleo12345/mybase3.git
python3 setup.py install
```


### 运行鉴权
``` bash
python src/auth.py
```


### 运行计费
``` bash
python src/acct.py
```


### 使用客户端测试服务 (目前项目内固定secret为: testing123)
``` bash
radtest  test  test  192.168.1.97  0  testing123
```

