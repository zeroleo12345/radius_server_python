# 第三方库
import sentry_sdk

SENTRY_DSN = config('SENTRY_DSN')
sentry_sdk.init(SENTRY_DSN)
