## Radius_Authenticator和Message_Authenticator
1. Radius 里面的 Authenticator
2. Eap-Message 对应的 Message-Authenticator
两者是不同的东西, Authenticator 存在于每个Radius报文里面(请求和应答), 而 Message-Authenticator 仅应用于 Eap 认证(报文有字段Eap-Message)
``` bash
    def Pack(self):
        """Create a ready-to-transmit authentication reply packet.
        Returns a RADIUS packet which can be directly transmitted
        to a RADIUS server. This differs with Packet() in how
        the authenticator is calculated.

        :return: raw packet
        :rtype:  string
        """
        assert(self.authenticator)
        assert(self.secret)

        if self.has_key('Message-Authenticator'):
            self['Message-Authenticator'] = self.MessageAuthenticator(self.authenticator)


    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return Packet(id=self.id, secret=self.secret,
                      authenticator=self.authenticator, dict=self.dict,
                      **attributes)
```

### eaool_test模拟器, 以下两句日志是 msk 的值 !!!  MS-MPPE-Recv-Key 是 [0:32], MS-MPPE-Send-Key 是 [32:64]
``` bash
MS-MPPE-Send-Key (sign) - hexdump(len=32): ff fc fc 8d f1 59 95 31 ea 67 e8 f4 a3 4c 9a 01 15 57 c5 3f d7 b5 2c 36 a1 a0 f0 54 0d 20 b9 7c
MS-MPPE-Recv-Key (crypt) - hexdump(len=32): 18 f4 c5 6a a3 11 ab a0 e3 96 63 bd ef 3e 7a fe 4b 73 91 d4 12 f1 5e 9d 7e 6a 76 fc 7a 3c 60 cc

PMK from EAPOL - hexdump(len=32): 3d 15 41 14 7f 1c 9a 0c 4a 37 76 9e a1 b0 3d 6a f4 44 d1 8d 26 21 95 71 50 b2 69 12 70 11 5d 07
WARNING: PMK mismatch
PMK from AS - hexdump(len=32): 18 f4 c5 6a a3 11 ab a0 e3 96 63 bd ef 3e 7a fe 4b 73 91 d4 12 f1 5e 9d 7e 6a 76 fc 7a 3c 60 cc
```

### RS 日志
```
msk: b'\x18\xf4\xc5j\xa3\x11\xab\xa0\xe3\x96c\xbd\xef>z\xfeKs\x91\xd4\x12\xf1^\x9d~jv\xfcz<`\xcc\xff\xfc\xfc\x8d\xf1Y\x951\xeag\xe8\xf4\xa3L\x9a\x01\x15W\xc5?\xd7\xb5,6\xa1\xa0\xf0T\r \xb9|', secret: b'testing123', authenticator: b'\xad}\xd5\x07Aw\x9c\xc5\t\xa3=AX\xbbg+'
```

### Python
```
>>> b'\x18\xf4\xc5j\xa3\x11\xab\xa0\xe3\x96c\xbd\xef>z\xfeKs\x91\xd4\x12\xf1^\x9d~jv\xfcz<`\xcc\xff\xfc\xfc\x8d\xf1Y\x951\xeag\xe8\xf4\xa3L\x9a\x01\x15W\xc5?\xd7\xb5,6\xa1\xa0\xf0T\r \xb9|'
b'\x18\xf4\xc5j\xa3\x11\xab\xa0\xe3\x96c\xbd\xef>z\xfeKs\x91\xd4\x12\xf1^\x9d~jv\xfcz<`\xcc\xff\xfc\xfc\x8d\xf1Y\x951\xeag\xe8\xf4\xa3L\x9a\x01\x15W\xc5?\xd7\xb5,6\xa1\xa0\xf0T\r \xb9|'
>>> b'\x18\xf4\xc5j\xa3\x11\xab\xa0\xe3\x96c\xbd\xef>z\xfeKs\x91\xd4\x12\xf1^\x9d~jv\xfcz<`\xcc\xff\xfc\xfc\x8d\xf1Y\x951\xeag\xe8\xf4\xa3L\x9a\x01\x15W\xc5?\xd7\xb5,6\xa1\xa0\xf0T\r \xb9|'.hex()
'18f4c56aa311aba0e39663bdef3e7afe4b7391d412f15e9d7e6a76fc7a3c60ccfffcfc8df1599531ea67e8f4a34c9a011557c53fd7b52c36a1a0f0540d20b97c'
>>> len('18f4c56aa311aba0e39663bdef3e7afe4b7391d412f15e9d7e6a76fc7a3c60ccfffcfc8df1599531ea67e8f4a34c9a011557c53fd7b52c36a1a0f0540d20b97c')
128
```
