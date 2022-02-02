import sys
import os
# 第三方库
import sentry_sdk
# 项目库
from utils.config import config
from library.crypto import EapCrypto
from loguru import logger as log


SENTRY_DSN = config('SENTRY_DSN', mandatory=False)
sentry_sdk.init(SENTRY_DSN)

USER_DB_URI = config('USER_DB_URI')     # sqlite:////app/data/db/users.db; mysql://username:password@localhost/test?charset=utf8mb4
RADIUS_DICTIONARY_DIR = config('RADIUS_DICTIONARY_DIR')
RADIUS_SECRET = str.encode(config('RADIUS_SECRET'))
RADIUS_PORT = config('RADIUS_PORT')
ACCOUNTING_INTERVAL = config('ACCOUNTING_INTERVAL', default=60, cast='@int')
API_URL = config('API_URL')

# Redis
REDIS_HOST = config('REDIS_HOST')
REDIS_PORT = config('REDIS_PORT')
REDIS_PASSWORD = config('REDIS_PASSWORD')
REDIS_DB = config('REDIS_DB')

# HOSTAPD 动态库
HOSTAPD_LIBRARY = config('HOSTAPD_LIBRARY')
CA_CERT = config('CA_CERT')
CLIENT_CERT = config('CLIENT_CERT')
PRIVATE_KEY = config('PRIVATE_KEY')
PRIVATE_KEY_PASSWORD = str(config('PRIVATE_KEY_PASSWORD'))
DH_FILE = config('DH_FILE')
libhostapd = EapCrypto(hostapd_library_path=HOSTAPD_LIBRARY, ca_cert_path=CA_CERT, client_cert_path=CLIENT_CERT,
                       private_key_path=PRIVATE_KEY, private_key_password=PRIVATE_KEY_PASSWORD, dh_file_path=DH_FILE)
# libhostapd.call_set_log_level(EapCrypto.MSG_EXCESSIVE)

# Log
LOG_HEADER = config('LOG_HEADER', default='')
LOG_DIR = config('LOG_DIR', default='')
LOG_LEVEL = config('LOG_LEVEL')
# 初始化日志
log.remove()    # workaround: https://github.com/Delgan/loguru/issues/208
log.add(sys.stderr, level=LOG_LEVEL)
if LOG_DIR and LOG_HEADER:
    log.info('enable log to file')
    log.add(os.path.join(LOG_DIR, LOG_HEADER + '_{time:YYYYMMDD_HHmmss_SSSSSS}.log'), rotation='00:00', level=LOG_LEVEL)
else:
    log.info('close log to file')
log.warning(f'log parameter. Log-Level: {LOG_LEVEL}, Log-Header: {LOG_HEADER}, Log-Directory: {LOG_DIR}')


def cleanup():
    log.info('cleanup')
    libhostapd.call_tls_deinit()
