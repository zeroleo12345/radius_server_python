import requests
# 项目库
from utils.config import config


class Prometheus(object):
    ENDPOINT = config('PROMETHEUS_ENDPOINT', default='http://metric:8428/prometheus/api/v1/import/prometheus')

    @classmethod
    def push_metric(cls, metrics: list):
        """
        curl -d 'foo{bar="baz"} 111 1746457233000' -X POST http://metric:8428/prometheus/api/v1/import/prometheus

        :param metrics:
            [
                upload_kb{username="111"} 1024 1755182746',
                download_kb{username="222"} 10240 1755182746',
                session_time{username="333"} 86400 1755182746',
            ]
        :return:
        """
        data = '\n'.join(metrics)
        headers = {
            "Content-Type": "text/plain; charset=utf-8"
        }
        response = requests.post(cls.ENDPOINT, data=data.encode('utf-8'), headers=headers, timeout=3)
        assert response.status_code == 204
