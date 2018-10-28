### 系统简介
pppoe 用户鉴权计费


### 安装依赖库
``` bash
pip3 install -r requirements/requirements.txt

git clone https://github.com/zeroleo12345/myclog-python.git
python3 setup.py install

git clone https://github.com/zeroleo12345/mybase3.git
python3 setup.py install

mkdir -p /data/log/
```


### 运行
- 鉴权
``` bash
python src/auth.py
```

- 计费
``` bash
python src/acct.py
```

- 使用客户端测试服务 (目前项目内固定secret为: testing123)
``` bash
radtest  test  test  192.168.1.97  0  testing123
```


### Supervisord
- 安装
``` bash
git clone git@github.com:zeroleo12345/supervisor.git
python2 setup.py install
```

- 启动Demon程序
``` bash
supervisord  -c /root/radius_server/etc/supervisord.ini
```

- 查看状态
``` bash
supervisorctl  -c /root/radius_server/etc/supervisord.ini status
```

