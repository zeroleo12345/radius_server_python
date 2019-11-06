## 系统简介
pppoe 用户鉴权计费


## 初始化

- 安装依赖库
``` bash
pip3 install -r requirements/requirements.txt   --trusted-host mirrors.aliyun.com --index-url http://mirrors.aliyun.com/pypi/simple
pip2 install git+https://gitee.com/zeroleo12345/supervisor-3.3.2.git        # 安装supervisor
```


- 环境变量
```
decrypt .env.x
cd run/data/ && rm users.db; sh init_database.sh      # 初始化sqlite3数据库
```


## 生产运行
- 启动 Supervisord Demon 程序
``` bash
sh bin/all_start.sh    # supervisord  -c /root/radius_server/etc/supervisord.ini
```


- 查看状态
``` bash
sh bin/status.sh       # supervisorctl  -c /root/radius_server/etc/supervisord.ini status
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


## 检查步骤
``` bash
1.1 /var/log/pppd.log 是否存在日志, 存在表示pppoe-server正常运行, 且有用户拨号.
1.2 /var/log/pppd.log 确认日志内容是否正常.

2. 检查交换机指示灯是否绿色. (绿色表示正常)

3. 检查run/log/auth*日志是否正常, 日志缓存已设为0 buffer, 可及时看到日志.
```

