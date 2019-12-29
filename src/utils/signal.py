import signal


# 只有在 gunicorn 下, 信号注册才生效.
class Signal:
    is_term = False
    is_usr1 = False
    is_usr2 = False
    # term_handlers = []

    @classmethod
    def signal_handler(cls, sig, frame):
        if sig == signal.SIGTERM:
            cls.is_term = True
            return
        if sig == signal.SIGUSR1:
            cls.is_usr1 = True
            return
        if sig == signal.SIGUSR2:
            cls.is_usr2 = True
            return
        # for handler in cls.term_handlers:
        #     handler()

    @classmethod
    def register(cls):
        """ 注册信号 """
        signal.signal(signal.SIGTERM, cls.signal_handler)
        # signal.signal(signal.SIGINT, cls.signal_handler)
        signal.signal(signal.SIGUSR1, cls.signal_handler)
        signal.signal(signal.SIGUSR2, cls.signal_handler)

    # @classmethod
    # def add_term_handler(cls, handler):
    #     cls.term_handlers.append(handler)
