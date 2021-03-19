import traceback
import sentry_sdk
from loguru import logger as log


def catch_exception():
    """
    捕捉所有异常, 打印日志
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                # 调用原函数
                return func(*args, **kwargs)
            except Exception as e:
                log.error(traceback.format_exc())
                sentry_sdk.capture_exception(e)

        return wrapper

    return decorator
