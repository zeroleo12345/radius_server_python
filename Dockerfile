# https://hub.docker.com/_/python/, 镜像名说明: 前缀python可选自url; 后缀:3.6-alpine为网页上的tag, 如不指定后缀, 则为:latest
FROM python:3.6.15-slim-bullseye
#FROM --platform=linux/amd64 python:3.6.15-slim-bullseye

# 一. 安装 linux package. (使用: 阿里云 alpine 镜像)
ADD requirements/sources.list.tencent /app/requirements/sources.list.tencent

RUN ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo Asia/Shanghai > /etc/timezone \
    && cp /app/requirements/sources.list.tencent  /etc/apt/sources.list \
    && apt-get update

RUN apt-get install -y build-essential git libssl-dev libnl-3-dev libnl-genl-3-dev libtalloc-dev libmariadb-dev \
    && apt-get install -y tcpdump procps curl inetutils-ping

# 二. 安装 python package.
ADD requirements/requirements.txt /app/requirements/requirements.txt

RUN pip3 install --no-cache-dir --upgrade pip --trusted-host mirrors.tencent.com --index-url https://mirrors.tencent.com/pypi/simple/ \
    && pip3 install --no-cache-dir -r /app/requirements/requirements.txt --trusted-host mirrors.tencent.com --index-url https://mirrors.tencent.com/pypi/simple/

# WORKDIR: 如果目录不存在, 则自动创建
WORKDIR /app/
ADD src /app/src/
ADD bin /app/bin/
ENV PYTHONPATH="/app/src:${PYTHONPATH}"
ENV PATH="${PATH}:/app/bin:/app/tools/simulator/bin"
ENV LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:/app/lib:/app/tools/simulator/lib"

# docker-compose.yml 会覆盖 entrypoint
#ENTRYPOINT ["/app/bin/web.sh"]
