# MacOS pyenv

- mise
```bash
mise list

mise install python 3.12.14 --verbose

pip install -r requirements/requirements.txt
```

- pycharm project intepreter
```
菜单 Settings... -> 
Python Interpreter -> Add Interpreter -> 
Virtualenv Environment -> Environment: Existing -> 点击... -> 
复制路径并点击OK:  ~/.local/share/mise/installs/python/3.12.14/bin/python
```


# Python 3.12 compatible package version
```
See `requirements/requirements.txt` for the production dependency lock and
`requirements/requirements-test.txt` for test tooling. Install them with the
Python 3.12.14 interpreter selected by `.mise.toml`.
```
