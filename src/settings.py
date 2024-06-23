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

DEBUG = config('DEBUG', default=True, cast='@bool')
DB_URI = config('DB_URI')     # sqlite:////app/data/db/users.db; mysql://username:password@localhost/test?charset=utf8mb4
RADIUS_DICTIONARY_DIR = config('RADIUS_DICTIONARY_DIR')
RADIUS_SECRET: bytes = str.encode(config('RADIUS_SECRET'))
RADIUS_PORT = config('RADIUS_PORT')
ACCOUNTING_INTERVAL = config('ACCOUNTING_INTERVAL', default=60, cast='@int')
API_URL = config('API_URL')

# Redis
REDIS_HOST = config('REDIS_HOST')
REDIS_PORT = config('REDIS_PORT')
REDIS_PASSWORD = config('REDIS_PASSWORD')
REDIS_DB = config('REDIS_DB')

# Log
LOG_HEADER = config('LOG_HEADER', default='')
LOG_DIR = config('LOG_DIR', default='')
LOG_LEVEL = config('LOG_LEVEL')
LOG_FILE_FORMAT = config('LOG_FILE_FORMAT', default="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {message}")
# 初始化日志
log.remove()    # workaround: https://github.com/Delgan/loguru/issues/208
if DEBUG:
    # log_console_format = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <level>{message}</level>"
    log_console_format = "{time:YYYY-MM-DD HH:mm:ss.SSS} | <level>{level: <8}</level> | <level>{message}</level>"
    log.add(sys.stderr, level=LOG_LEVEL, format=log_console_format, colorize=False)
if LOG_DIR and LOG_HEADER:
    log.info('enable log to file')
    log.add(os.path.join(LOG_DIR, LOG_HEADER + '_{time:YYYYMMDD_HHmmss_SSSSSS}.log'), rotation='00:00', level=LOG_LEVEL, format=LOG_FILE_FORMAT)
else:
    log.info('close log to file')
log.info(f'Log parameter. Level: {LOG_LEVEL}, Header: {LOG_HEADER}, Directory: {LOG_DIR}')
