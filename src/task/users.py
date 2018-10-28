import requests
# 第三方库
# 自己的库
from settings import API_URL
from auth.models import User


def sync_users_data():
    response = requests.get(f'{API_URL}/user/sync')
    data = response.json()['data']
    for item in data:
        username = item['username']
        password = item['password']
        expired_at = item['expired_at']
        User.replace(username=username, password=password, expired_at=expired_at)
