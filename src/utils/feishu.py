import requests
import json
import time
# 第三方库
from utils.config import settings
from loguru import logger as log


class Feishu(object):
    class Token(object):
        def __init__(self, token='', ttl=-1):
            self.token = token
            self.expired_at = int(time.time()) + ttl

    # Must:
    FEISHU_APP_ID = settings.get('FEISHU_APP_ID', default='')
    FEISHU_APP_SECRET = settings.get('FEISHU_APP_SECRET', default='')
    # Optional:
    FEISHU_MAC_CHAT_ID = settings.get('FEISHU_MAC_CHAT_ID', default='oc_3a7065d01efdb36d949088341aada466')            # MAC请求放通群
    FEISHU_SESSION_CHAT_ID = settings.get('FEISHU_SESSION_CHAT_ID', default='oc_19b2404bb0917fc066cce1b3a58c3558')    # 多拨告警群
    #
    _ACCESS_TOKEN = Token()

    """
    获取access_token
    https://feishu.apifox.cn/api-58156651

    POST /open-apis/auth/v3/tenant_access_token/internal HTTP/1.1
    Host: open.feishu.cn
    Authorization: Bearer <token>
    Content-Type: application/json
    Content-Length: 81

    {
        "app_id": "cli_slkdjalaxxxxxx",
        "app_secret": "dskLLdkasdxxxxxx"
    }

    :return:
    {
        "code": 0,
        "msg": "ok",
        "tenant_access_token": "t-caecc734c2e3328a62489fe0648c4xxxxxx",
        "expire": 7200
    }
    """
    @classmethod
    def get_access_token(cls) -> str:
        assert cls.FEISHU_APP_ID and cls.FEISHU_APP_SECRET
        if int(time.time()) > cls._ACCESS_TOKEN.expired_at:
            data = {
                'app_id': cls.FEISHU_APP_ID,
                'app_secret': cls.FEISHU_APP_SECRET,
            }
            response = requests.post('https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal/', json=data)
            assert response.ok
            body = response.json()
            log.debug(f'API get_access_token: {body}')
            if body['code'] != 0:
                raise Exception('飞书获取access_token失败')
            cls._ACCESS_TOKEN = cls.Token(token=body['tenant_access_token'], ttl=body['expire'])
        log.debug(f'fetched access token: {cls._ACCESS_TOKEN.token}')
        return cls._ACCESS_TOKEN.token

    """
    发送消息
    https://feishu.apifox.cn/api-58348294

    POST /open-apis/im/v1/messages?receive_id_type=chat_id HTTP/1.1
    Host: open.feishu.cn
    Authorization: Bearer <token>
    Content-Type: application/json
    Content-Length: 189

    {
        "receive_id": "ou_7d8a6e6df7621556ce0d21922bxxxxxx",
        "msg_type": "text",
        "content": "{\"text\":\"test content\"}",
        "uuid": "a0d69e20-1dd1-458b-k525-dfecaxxxxxx"
    }

    :return:
    {
        "code": 0,
        "msg": "success",
        "data": {
            "message_id": "om_dc13264520392913993dd05xxxxxx",
            "root_id": "om_40eb06e7b84dc71c03e009ad3cxxxxxx",
            "parent_id": "om_d4be107c616aed9c1da8ed8xxxxxx",
            "msg_type": "card",
            "create_time": "1615380573411",
            "update_time": "1615380573411",
            "deleted": false,
            "updated": false,
            "chat_id": "oc_5ad11d72b830411d72xxxxxx",
            "sender": {
                "id": "cli_9f427eec54ae901b",
                "id_type": "app_id",
                "sender_type": "app",
                "tenant_key": "736588c926xxxxxx"
            },
            "body": {
                "content": "text:测试消息"
            },
            "mentions": [
                {
                    "key": "@_user_1",
                    "id": "ou_155184d1e73cbfb8973e5a9exxxxxx",
                    "id_type": "open_id",
                    "name": "Tom",
                    "tenant_key": "736588c9260xxxxxx"
                }
            ],
            "upper_message_id": "om_40eb06e7b84dc71c03e009adxxxxxx"
        }
    }
    """
    @classmethod
    def send_group_msg(cls, receiver_id: str, text: str):
        access_token = cls.get_access_token()
        #
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        data = {
            'receive_id': receiver_id,
            'msg_type': 'text',
            'content': json.dumps({
                'text': text,
            })
        }
        response = requests.post('https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id', json=data, headers=headers)
        body = response.json()
        log.debug(f'API send_group_msg: {body}')
        assert response.ok
        if body['code'] != 0:
            raise Exception('飞书群消息发送失败')

    @classmethod
    def send_webhook_msg(cls, webhook_url: str, text: str):
        data = {
            'msg_type': 'text',
            'content': {
                'text': text,
            }
        }
        response = requests.post(webhook_url, json=data)
        assert response.ok
        body = response.json()
        log.debug(f'API send_webhook_msg: {body}')
        if body['code'] != 0:
            raise Exception('飞书webhook消息发送失败')
