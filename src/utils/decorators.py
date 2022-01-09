"""
Reference: https://www.liaoxuefeng.com/wiki/1016959663602400/1017451662295584
1. 装饰器不需传入参数, decorator就是一个返回函数的高阶函数
2. 装饰器需要传入参数，那就需要编写一个返回decorator的高阶函数
"""

import traceback
import sentry_sdk
from loguru import logger as log


def catch_exception(func):
    """
    捕捉所有异常, 打印日志
    """
    def wrapper(*args, **kwargs):
        try:
            # 调用原函数
            return func(*args, **kwargs)
        except Exception as e:
            log.critical(traceback.format_exc())
            sentry_sdk.capture_exception(e)

    return wrapper
