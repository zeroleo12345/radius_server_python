import requests
import time
# 第三方库
from utils.config import settings
from loguru import logger as log


class Dingding(object):
    class Token(object):
        def __init__(self, token='', ttl=-1):
            self.token = token
            self.expired_at = int(time.time()) + ttl

    # Must:
    DINGDING_APP_ID = settings.get('DINGDING_APP_ID')
    DINGDING_APP_SECRET = settings.get('DINGDING_APP_SECRET')
    DINGDING_ROBOT_CODE = settings.get('DINGDING_ROBOT_CODE', default='dingqnettcbcq4tpecq7')
    # Optional:
    DINGDING_MAC_CHAT_ID = settings.get('DINGDING_MAC_CHAT_ID', default='cidVhnIuNh9n5Q0MoN8ddMqNw==')            # MAC请求放通群
    DINGDING_SESSION_CHAT_ID = settings.get('DINGDING_SESSION_CHAT_ID', default='cidVhnIuNh9n5Q0MoN8ddMqNw==')    # 多拨告警群
    #
    _ACCESS_TOKEN = Token()

    """
    获取access_token
    https://open.dingtalk.com/document/development/obtain-the-access-token-of-an-internal-app

    POST /v1.0/oauth2/accessToken HTTP/1.1
    Host:api.dingtalk.com
    Content-Type:application/json

    {
      "appKey" : "dingeqqpkv3xxxxxx",
      "appSecret" : "GT-lsu-taDAxxxsTsxxxx"
    }

    :return:
    {
      "accessToken" : "fw8ef8we8f76e6f7s8dxxxx",
      "expireIn" : 7200
    }
    """
    @classmethod
    def get_access_token(cls) -> str:
        if int(time.time()) > cls._ACCESS_TOKEN.expired_at:
            data = {
                'appKey': cls.DINGDING_APP_ID,
                'appSecret': cls.DINGDING_APP_SECRET,
            }
            response = requests.post('https://api.dingtalk.com/v1.0/oauth2/accessToken', json=data)
            body = response.json()
            log.debug(f'API get_access_token: {body}')
            cls._ACCESS_TOKEN = cls.Token(token=body['accessToken'], ttl=body['expireIn'])
        log.debug(f'fetched access token: {cls._ACCESS_TOKEN.token}')
        return cls._ACCESS_TOKEN.token

    """
    发送应用消息
    https://open.dingtalk.com/document/development/the-robot-sends-a-group-message

    POST /v1.0/robot/groupMessages/send HTTP/1.1
    Host:api.dingtalk.com
    x-acs-dingtalk-access-token:nvosnghskaknz8xxxxxx
    Content-Type:application/json

    {
      "msgParam" : "{\"content\":\"钉钉，让进步发生\"}",
      "msgKey" : "sampleText",
      "openConversationId" : "cid6KeBBLoveMJOGXoYKF5xxxxxxx==",
      "robotCode" : "dingue4kfzdxbynxxxxxx",
      "coolAppCode" : "COOLAPP-1-10182EEDD1AC0BA60xxxxxx"
    }

    :return:
    {
      "processQueryKey" : "jkasdfb8va9hnxxxxxx"
    }
    """
    @classmethod
    def send_group_msg(cls, receiver_id: str, text: str):
        headers = {
            'x-acs-dingtalk-access-token': cls.get_access_token(),
        }
        data = {
            'msgParam': f'{{"content":"{text}"}}',
            'msgKey': 'sampleText',
            'openConversationId': receiver_id,
            'robotCode': cls.DINGDING_ROBOT_CODE,
        }
        response = requests.post('https://api.dingtalk.com/v1.0/robot/groupMessages/send', json=data, headers=headers)
        body = response.json()
        log.debug(f'API send_group_msg: {body}')
        assert response.ok
