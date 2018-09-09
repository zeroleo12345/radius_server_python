# 安装程序
yum -y install docker

# 启动服务
service docker start  # systemctl start docker.service

# 设置开机启动
systemctl enable docker

# 安装docker-compose工具
pip install docker-compose

# 重启docker
systemctl restart docker

## Linux下docker镜像加速 (非Mac)
mkdir -p /etc/docker
cat > /etc/docker/daemon.json << EOF
{
  "registry-mirrors": ["https://0ryfbg22.mirror.aliyuncs.com"]
}
EOF
systemctl daemon-reload
systemctl restart docker
