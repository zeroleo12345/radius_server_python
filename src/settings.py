from decouple import config
# 自己的库
from mybase.mylog3 import log 

USER_DB = config('USER_DB')
DICTIONARY_DIR = config('DICTIONARY_DIR')
SECRET = str.encode(config('SECRET'))
API_URL = config('API_URL')
LOG_HEADER = config('LOG_HEADER')

log.init(header=LOG_HEADER, directory="/data/log", level="debug", max_buffer=0, max_line=100000)
