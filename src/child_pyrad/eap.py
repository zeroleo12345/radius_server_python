class Eap(object):
    # EAP Code
    CODE_EAP_REQUEST = 1
    CODE_EAP_RESPONSE = 2
    CODE_EAP_SUCCESS = 3
    CODE_EAP_FAILURE = 4

    #
    CODE_MSCHAPV2_CHALLENGE = 1
    CODE_MSCHAPV2_RESPONSE = 2
    CODE_MSCHAPV2_SUCCESS = 3
    CODE_MSCHAPV2_FAILURE = 4

    # phase2 EAP Type
    TYPE_EAP_IDENTITY = 1
    TYPE_EAP_NOTIFICATION = 2
    TYPE_EAP_NAK = 3
    TYPE_EAP_GTC = 6
    TYPE_EAP_SIM = 18           # 0x12
    TYPE_EAP_AKA = 23           # 0x17
    TYPE_EAP_PEAP = 25          # 0x19
    TYPE_EAP_MSCHAPV2 = 26      # 0x1a
    TYPE_EAP_TLV = 33           # 0x21

    # EAP-TLV类型
    TYPE_RESULT_TLV_SUCCESS = 1
    TYPE_RESULT_TLV_FAILURE = 2
    TYPE_RESULT_TLV = 3

    @staticmethod
    def get_next_id(identifier):
        if identifier == 0:
            return 1
            # return random.randrange(1, 255)
        elif identifier + 1 > 255:
            return 1

        return identifier + 1

    @staticmethod
    def split_eap_message(eap_messages: bytes) -> list:
        """
        split EAP-Message field to multiple
        each max len = 255 - 2 (header byte)

        :input: EAP-Message binary string
        :return: EAP-Message[]. each contain binary string.
        """
        if len(eap_messages) < 253:
            return [eap_messages]
        _stop = len(eap_messages)
        _step = 253
        return [eap_messages[pos:pos+_step] for pos in range(0, _stop, _step)]

    @staticmethod
    def merge_eap_message(eap_messages) -> bytes:
        """
        concatenation multiple EAP-Message field.
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Type      |    Length     |     String...
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        :input: EAP-Message[]. each contain binary string (without type | length)
        :return: EAP-Message binary string
        """
        assert isinstance(eap_messages, list)
        result = b''
        # if len(eap_messages) == 1:
        #     return eap_messages[0]
        for eap_message in eap_messages:
            if isinstance(eap_message, str):
                result += eap_message.encode()
            else:
                result += eap_message
        return result

    @classmethod
    def is_eap_peap(cls, type):
        return type == cls.TYPE_EAP_PEAP
