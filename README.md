### 系统简介
pppoe 用户鉴权计费


### 初始化
- 安装依赖库
``` bash
pip3 install -r requirements/requirements.txt

git clone https://github.com/zeroleo12345/myclog-python.git
python3 setup.py install
```

- 环境变量
```
deceypt .env.x

# 初始化sqlite3数据库
rm data/users.db
sh migrate/init_db.sh
```

### 开发调试运行
- 鉴权
``` bash
python src/auth.py
```

- 计费
``` bash
python src/acct.py
```

- 使用客户端radtest测试服务 (来自freeradius工具包)
``` bash
# 目前项目内固定secret为: testing123
radtest  test  test  192.168.1.97  0  testing123
```


### 生产运行
- 安装 Supervisord
``` bash
git clone git@github.com:zeroleo12345/supervisor.git
python2 setup.py install
```

- 启动 Supervisord Demon 程序
``` bash
supervisord  -c /root/radius_server/etc/supervisord.ini
```

- 查看状态
``` bash
supervisorctl  -c /root/radius_server/etc/supervisord.ini status
```

