
git clone https://github.com/pyenv/pyenv.git ~/.pyenv

echo 'export PYENV_ROOT="$HOME/.pyenv"' | tee -a ~/.bashrc | tee -a ~/.zshrc

echo 'export PATH="$PYENV_ROOT/bin:$PATH"' | tee -a ~/.bashrc | tee -a ~/.zshrc

echo -e 'if command -v pyenv 1>/dev/null 2>&1; then\n eval "$(pyenv init -)"\nfi' | tee -a ~/.bashrc | tee -a ~/.zshrc

# 使用镜像: v=3.6.5|wget http://mirrors.sohu.com/python/$v/Python-$v.tar.xz -P ~/.pyenv/cache/;pyenv install $v
pyenv install  3.6.5
