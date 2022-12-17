import os
# 项目库
from loguru import logger as log


def get_dictionaries(directory):
    if not os.path.exists(directory):
        raise Exception('directory:{} not exist'.format(directory))
    log.info(f'dicts directory: {directory}')
    # 遍历目录一次
    root, dirs, files = next(os.walk(directory))
    dictionaries = []
    for filename in files:
        if filename.startswith('dictionary.'):
            log.debug(f'load dictionary: {filename}')
            dictionaries.append(os.path.join(root, filename))
        else:
            log.debug(f'ignore dictionary: {filename}')
    return dictionaries
