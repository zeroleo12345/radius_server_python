import requests
# 第三方库
from decouple import config
# 自己的库
from settings import API_URL
from auth.models import User

def sync_users_data():
    # TODO
    response = requests.get(f'{API_URL}/users'))
    data = response.json()['data']
    for item in data:
        username = item['username']
        password = item['password']
        is_valid = item['is_valid']
        User.replace(username=username, password=password, is_valid=is_valid)

