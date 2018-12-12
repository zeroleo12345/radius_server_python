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
ACCT_INTERVAL = config('ACCT_INTERVAL', cast=int)
API_URL = config('API_URL')
LOG_HEADER = config('LOG_HEADER')
LOG_DIR = config('LOG_DIR')
LOG_LEVEL = config('LOG_LEVEL')

log.init(header=LOG_HEADER, directory=LOG_DIR, level=LOG_LEVEL, max_buffer=0, max_line=100000)
