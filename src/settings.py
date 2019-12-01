# 第三方库
from decouple import config
import sentry_sdk
# 自己的库
from mybase3.mylog3 import log

SENTRY_DSN = config('SENTRY_DSN')
sentry_sdk.init(SENTRY_DSN)

USER_DB = config('USER_DB')
DICTIONARY_DIR = config('DICTIONARY_DIR')
SECRET = str.encode(config('SECRET'))
ACCT_INTERVAL = config('ACCT_INTERVAL', default=60, cast=int)
API_URL = config('API_URL')
LOG_HEADER = config('LOG_HEADER')
LOG_DIR = config('LOG_DIR')
LOG_LEVEL = config('LOG_LEVEL')
LOG_BUFFER_SIZE = config('LOG_BUFFER_SIZE', default=0, cast=int)

log.init(header=LOG_HEADER, directory=LOG_DIR, level=LOG_LEVEL, max_buffer=LOG_BUFFER_SIZE, max_line=100000)
log.i('start')
