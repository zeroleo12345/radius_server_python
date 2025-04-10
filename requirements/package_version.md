# MacOS pyenv

- mise
```bash
mise install python 3.7.17 --verbose
pip install -r requirements/requirements.txt
```

- pycharm project intepreter
```
菜单 Settings... -> 
Python Interpreter -> Add Interpreter -> 
Virtualenv Environment -> Environment: Existing -> 点击... -> 
复制路径并点击OK:  ~/.local/share/mise/installs/python/3.7.17/bin/python
```


# running package version
```
aiocontextvars==0.2.2
certifi==2022.9.14
cffi==1.15.1
chardet==3.0.4
contextvars==2.4
cryptography==3.2
dynaconf==3.1.2
gevent==1.3.7
greenlet==1.1.3
idna==2.7
immutables==0.19
importlib-resources==5.4.0
loguru==0.5.3
netaddr==0.8.0
pycparser==2.21
PyMySQL==0.9.3
python-dateutil==2.7.5
pytz==2019.1
redis==3.3.11
requests==2.20.0
sentry-sdk==0.5.5
six==1.15.0
typing_extensions==4.1.1
urllib3==1.24.3
zipp==3.6.0
```