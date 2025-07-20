import sys
import os
# 第三方库
import sentry_sdk
# 项目库
from utils.config import config
from loguru import logger as log


SENTRY_DSN = config('SENTRY_DSN', mandatory=False)
SENTRY_PROXY = config('SENTRY_PROXY', default='')
sentry_sdk.init(
    dsn=SENTRY_DSN,
    debug=False,
    http_proxy=SENTRY_PROXY,
    https_proxy=SENTRY_PROXY,
)

RADIUS_DICTIONARY_DIR = config('RADIUS_DICTIONARY_DIR')
RADIUS_SECRET: bytes = str.encode(config('RADIUS_SECRET'))
RADIUS_LISTEN_IP = config('RADIUS_LISTEN_IP', default='')
RADIUS_LISTEN_PORT = config('RADIUS_LISTEN_PORT', default='')
ACCOUNTING_INTERVAL = config('ACCOUNTING_INTERVAL', default=60, cast='@int')
API_URL = config('API_URL')

# DB
DATABASE_URI = config('DATABASE_URI')

# Redis
REDIS_HOST = config('REDIS_HOST')
REDIS_PORT = config('REDIS_PORT')
REDIS_PASSWORD = config('REDIS_PASSWORD')
REDIS_DB = config('REDIS_DB')

# Log
LOG_LEVEL = config('LOG_LEVEL')
# 初始化日志
log.remove()    # workaround: https://github.com/Delgan/loguru/issues/208
# log_console_format = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <level>{message}</level>"
log_console_format = "{time:YYYY-MM-DD HH:mm:ss.SSS} | <level>{level: <8}</level> | <level>{message}</level>"
log.add(sys.stderr, level=LOG_LEVEL, format=log_console_format, colorize=False)     # print log to terminal
log.info(f'Log parameter. Level: {LOG_LEVEL}')
