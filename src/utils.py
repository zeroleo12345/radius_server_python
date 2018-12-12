import os


def get_dictionaries(directory):
    if not os.path.exists(dir):
        raise Exception('directory:{} not exist'.format(directory))
    # 遍历目录一次
    root, dirs, files = next(os.walk(directory))
    dictionaries = [os.path.join(root, f) for f in files]
    return dictionaries
