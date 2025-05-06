import requests
# 项目库
from utils.config import config


class Prometheus(object):
    ENDPOINT = config('PROMETHEUS_ENDPOINT', default='http://metric:8428/prometheus/api/v1/import/prometheus')

    @classmethod
    def push_metric(cls, data: str):
        # curl -d 'foo{bar="baz"} 111 1746457233000' -X POST http://metric:8428/prometheus/api/v1/import/prometheus
        data = """
        upload_bytes{username="testuser"} 5012
        download_bytes{username="testuser"} 1024
        """

        headers = {
            "Content-Type": "text/plain; charset=utf-8"
        }
        response = requests.post(cls.ENDPOINT, data=data.encode('utf-8'), headers=headers, timeout=3)
        assert response.status_code == 204
