import json
import requests
# 项目库
from utils.config import config


class Prometheus(object):
    ENDPOINT = config('PROMETHEUS_ENDPOINT', default='http://metric:8428/prometheus/api/v1/import/prometheus')

    @classmethod
    def push_metric(cls, receiver_id: str, text: str):
        # curl -d 'foo{bar="baz"} 111 1746457233000' -X POST http://metric:8428/prometheus/api/v1/import/prometheus
        pass
