import json
import requests
# 第三方库
from utils.config import config


class Feishu(object):
    FEISHU_APP_ID = config('FEISHU_APP_ID')
    FEISHU_APP_SECRET = config('FEISHU_APP_SECRET')
    FEISHU_CHARGE_CHAT_ID = config('FEISHU_CHARGE_CHAT_ID', default='oc_a4bc2f10dd9ec84f08f2bbcaa82e08cd')
    FEISHU_MAC_CHAT_ID = config('FEISHU_MAC_CHAT_ID', default='oc_3a7065d01efdb36d949088341aada466')
    FEISHU_SESSION_CHAT_ID = config('FEISHU_SESSION_CHAT_ID', default='oc_19b2404bb0917fc066cce1b3a58c3558')

    @classmethod
    def send_groud_msg(cls, receiver_id: str, text: str):
        data = {
            'app_id': cls.FEISHU_APP_ID,
            'app_secret': cls.FEISHU_APP_SECRET,
        }
        response = requests.post('https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal/', json=data)
        assert response.ok
        body = json.loads(response.text)
        if body['code'] != 0:
            raise Exception('飞书获取access_token失败')
        access_token = response.json()['tenant_access_token']
        #
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        data = {
            'chat_id': receiver_id,
            'msg_type': 'text',
            'content': {
                'text': text,
            }
        }
        response = requests.post('https://open.feishu.cn/open-apis/message/v4/send/', json=data, headers=headers)
        assert response.ok
        body = json.loads(response.text)
        if body['code'] != 0:
            raise Exception('信息发送到飞书败')
