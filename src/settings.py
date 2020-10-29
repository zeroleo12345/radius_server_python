# 第三方库
from decouple import config
import sentry_sdk
# 自己的库
from mybase3.mylog3 import log

SENTRY_DSN = config('SENTRY_DSN')
sentry_sdk.init(SENTRY_DSN)

USER_SQLITE_DB = config('USER_SQLITE_DB')
RADIUS_DICTIONARY_DIR = config('RADIUS_DICTIONARY_DIR')
RADIUS_SECRET = str.encode(config('RADIUS_SECRET'))
ACCOUNTING_INTERVAL = config('ACCOUNTING_INTERVAL', default=60, cast=int)
API_URL = config('API_URL')

# Log
LOG_HEADER = config('LOG_HEADER')
LOG_DIR = config('LOG_DIR')
LOG_LEVEL = config('LOG_LEVEL')
LOG_BUFFER_SIZE = config('LOG_BUFFER_SIZE', default=0, cast=int)

# Redis
REDIS_HOST = config('REDIS_HOST')
REDIS_PORT = config('REDIS_PORT')
REDIS_PASSWORD = config('REDIS_PASSWORD')
REDIS_DB = config('REDIS_DB')

# 初始化日志
log.init(header=LOG_HEADER, directory=LOG_DIR, level=LOG_LEVEL, max_buffer=LOG_BUFFER_SIZE, max_line=100000)
log.i(f'start log. LOG_LEVEL: {LOG_LEVEL}, LOG_BUFFER_SIZE: {LOG_BUFFER_SIZE}, LOG_HEADER: {LOG_HEADER}, LOG_DIR: {LOG_DIR}')
