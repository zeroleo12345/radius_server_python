## 系统简介
pppoe 用户鉴权计费


## 初始化
- 安装依赖库
``` bash
pip3 install -r requirements/requirements.txt

# 安装supervisor
pip2 install git+https://gitee.com/zeroleo12345/supervisor-3.3.2.git
mkdir -p /log/supervisord
```

- 环境变量
```
deceypt .env.x

# 初始化sqlite3数据库
rm run/data/users.db
sh run/data/init_database.sh
```

## 生产运行
- 启动 Supervisord Demon 程序
``` bash
supervisord  -c /root/radius_server/etc/supervisord.ini
```

- 查看状态
``` bash
supervisorctl  -c /root/radius_server/etc/supervisord.ini status
```


## 开发调试运行
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


