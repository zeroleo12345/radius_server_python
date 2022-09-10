# https://hub.docker.com/_/python/, 镜像名说明: 前缀python可选自url; 后缀:3.6-alpine为网页上的tag, 如不指定后缀, 则为:latest
FROM python:3.6.12-slim-stretch

ADD requirements /app/requirements/

# 一. 安装 linux package. (使用: 阿里云 alpine 镜像)
# 二. 安装 python package.
# 三. 清理不需保留的包 且 安装需保留的包. gcc g++ freeradius-utils
RUN ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo Asia/Shanghai > /etc/timezone \
    && cp /app/requirements/sources.list.aliyun  /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y build-essential git libssl1.0-dev libnl-3-dev libtalloc-dev libmariadbclient-dev \
    && apt-get install -y tcpdump procps curl inetutils-ping \
    && apt-get purge --auto-remove \
    && rm -rf /tmp/* /var/lib/apt/lists/* \
    && apt-get clean -y
RUN pip3 install --no-cache-dir --upgrade pip --trusted-host mirrors.aliyun.com --index-url http://mirrors.aliyun.com/pypi/simple \
    && pip3 install --no-cache-dir -r /app/requirements/requirements-test.txt --trusted-host mirrors.aliyun.com --index-url http://mirrors.aliyun.com/pypi/simple

# WORKDIR: 如果目录不存在, 则自动创建
WORKDIR /app/
ADD src /app/src/
ADD bin /app/bin/
ENV PYTHONPATH="/app/src:${PYTHONPATH}"
ENV PATH="${PATH}:/app/bin:/app/tools/simulator/bin"
ENV LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:/app/lib:/app/tools/simulator/lib"

# docker-compose.yml 会覆盖 entrypoint
#ENTRYPOINT ["/app/bin/web.sh"]
