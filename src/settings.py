from decouple import config
# 自己的库
from mybase3.mylog3 import log

USER_DB = config('USER_DB')
DICTIONARY_DIR = config('DICTIONARY_DIR')
SECRET = str.encode(config('SECRET'))
API_URL = config('API_URL')
LOG_HEADER = config('LOG_HEADER')
LOG_DIR = config('LOG_DIR')
LOG_LEVEL = config('LOG_LEVEL')

log.init(header=LOG_HEADER, directory=LOG_DIR, level=LOG_LEVEL, max_buffer=0, max_line=100000)
