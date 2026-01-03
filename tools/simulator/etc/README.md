# 修改openssl配置(可选)
- RedHat 6.7
    vim /usr/local/ssl/openssl.cnf

- MacOS
> LibreSSL 不是标准的 OpenSSL
``` bash
    alias openssl=/usr/bin/openssl
    # alias openssl=/$HOMEBREW_PREFIX/bin/openssl
    openssl version
        LibreSSL 3.3.6
    openssl version -a | grep OPENSSLDIR
        OPENSSLDIR: "/private/etc/ssl"
    # sudo ln -s /usr/local/etc/openssl/openssl.cnf   /private/etc/ssl/openssl.cnf
    # vim /private/etc/ssl/openssl.cnf

    [ CA_default ]
    #dir     = ./demoCA      # TSA root directory
    dir     = ./     # TSA root directory
```

# 进入目录
cd ~/github/radius_server_python/tools/simulator/etc/certs


# 清理
rm -rf  ./newcerts/  ./*.old  ./*.attr  index.txt  serial  dh  *.csr *.key *.cer *.p12


# 创建 CA状态信息 数据文件: index.txt
touch index.txt


# 生成dh文件: dh
openssl dhparam -out ./dh 2048

cat ./dh

# 报错则更换序列号: ERROR:Serial number 99 has already been issued
[ ! -f serial ] && echo 01 > serial

cat ./serial

# 生成CA根证书私钥(KEY): ca.key
openssl genrsa -out ./radius.ca.key 2048

cat ./radius.ca.key

# 生成 ca.cer
openssl req -config ../openssl.macOS.cnf -new -sha256 -x509 -days 36500 -key ./radius.ca.key -out ./radius.ca.cer -subj "/C=CN/ST=GuangDong/L=GuangZhou/O=zhuzaiyuan/OU=zhuzaiyuan/CN=WIFI/emailAddress=10000@gmail.com"

cat ./radius.ca.cer

    # 生成CA根证书(CER). 提供CA根证书私钥
    | 字段         | 含义    | 你填的值                                |
    | ------------ | ------- | --------------------------------------- |
    | C            | 国家    | CN (两位国家代码)                       |
    | ST           | 省 / 州 | GuangDong                               |
    | L            | 城市    | GuangZhou                               |
    | O            | 组织    | zhuzaiyuan                              |
    | OU           | 组织单位| zhuzaiyuan                              |
    | CN           | 通用名  | WIFI                                    |
    | emailAddress | 邮箱    | 10000@gmail.com                          |
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) [AU]:CN
    State or Province Name (full name) [Some-State]:GuangDong
    Locality Name (eg, city) []:GuangZhou
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:zhuzaiyuan
    Organizational Unit Name (eg, section) []:zhuzaiyuan
    Common Name (e.g. server FQDN or YOUR name) []:WIFI
    Email Address []:10000@gmail.com


# 生成服务端私钥(KEY), 并使用des3加密: server.key
openssl genrsa  -des3 -passout pass:123456  -out ./radius.server.key 2048

cat ./radius.server.key

    Generating RSA private key, 2048 bit long modulus
    ...............................................+++
    ..............................................+++
    e is 65537 (0x10001)
    Enter pass phrase for server.key:123456
    Verifying - Enter pass phrase for server.key:123456


# 生成服务端证书签名请求(CSR). 提供服务端私钥: server.csr
openssl req -config ../openssl.macOS.cnf -new -sha256 -key ./radius.server.key  -passin pass:123456 -out ./radius.server.csr -subj "/C=CN/ST=GuangDong/L=GuangZhou/O=zhuzaiyuan/OU=zhuzaiyuan/CN=WIFI/emailAddress=10000@gmail.com"

cat ./radius.server.csr

    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) [AU]:CN
    State or Province Name (full name) [Some-State]:GuangDong
    Locality Name (eg, city) []:GuangZhou
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:zhuzaiyuan
    Organizational Unit Name (eg, section) []:zhuzaiyuan
    Common Name (e.g. server FQDN or YOUR name) []:WIFI
    Email Address []:10000@gmail.com

    Please enter the following 'extra' attributes
    to be sent with your certificate request
    A challenge password []:123456
    An optional company name []:WIFI


# 确认必要文件已存在
ls -al index.txt serial


# 生成服务端证书(CER). 提供CA根证书私钥、CA根证书、服务端证书签名请求: server.cer
> 可以指定 -notext 不生成 Certificate Details: 文本
mkdir newcerts
openssl ca -config ../openssl.macOS.cnf -md sha256 -days 36500 -keyfile ./radius.ca.key -cert ./radius.ca.cer -in ./radius.server.csr -out ./radius.server.cer

cat radius.server.cer

    Using configuration from /usr/local/ssl/openssl.cnf
    Check that the request matches the signature
    Signature ok
    Certificate Details:
            Serial Number: 1 (0x1)
            Validity
                Not Before: Jan 23 12:12:07 2016 GMT
                Not After : Jan 22 12:12:07 2017 GMT
            Subject:
                countryName               = CN
                stateOrProvinceName       = GD
                organizationName          = E
                organizationalUnitName    = EIS
                commonName                = MAN
                emailAddress              = email
            X509v3 extensions:
                X509v3 Basic Constraints:
                    CA:FALSE
                Netscape Comment:
                    OpenSSL Generated Certificate
                X509v3 Subject Key Identifier:
                    6F:E5:BE:98:0D:80:CB:69:88:DF:A4:24:22:98:FB:68:30:A5:70:FF
                X509v3 Authority Key Identifier:
                    keyid:BE:E5:7D:C1:8A:23:94:0B:43:6E:B5:33:FC:ED:D7:D8:5C:76:38:EA

    Certificate is to be certified until Jan 22 12:12:07 2017 GMT (365 days)
    Sign the certificate? [y/n]:y
    1 out of 1 certificate requests certified, commit? [y/n]y
    Write out database with 1 new entries
    Data Base Updated


# 合成p12证书文件(AC侧需要使用.p12证书): certificate.p12
openssl pkcs12 -export -out radius.certificate.p12 -inkey ./radius.server.key -in ./radius.server.cer

    Enter pass phrase for server.key: 123456
    Enter Export Password: 123456
    Verifying - Enter Export Password: 123456


# 查看公钥CER过期时间
openssl x509 -noout -dates -in ./radius.server.cer


# 验证私钥KEY密码
openssl rsa -check -in ./radius.server.key

    Enter pass phrase for server.key: 123456


## hostapd 不需要用到 client 证书, 用于 mTLS !!!!
# 生成客户端私钥: client.key
openssl genrsa -des3 -out ./radius.client.key 2048

    Generating RSA private key, 2048 bit long modulus
    ....++++++++++++
    .++++++++++++
    e is 65537 (0x10001)
    Enter pass phrase for client.key: 123456
    Verifying - Enter pass phrase for client.key: 123456


# 通过客户端私钥, 生成客户端证书签名请求
openssl req -config ../openssl.macOS.cnf -new -days 36500 -key ./radius.client.key -out ./radius.client.csr -subj "/C=CN/ST=GuangDong/L=GuangZhou/O=client/OU=client/CN=WIFI/emailAddress=10000@gmail.com"

    Enter pass phrase for ./client.key: 123456


# 通过CA根证书私钥、CA根证书、客户端证书签名请求, 生成客户端证书
openssl ca -config ../openssl.macOS.cnf -days 36500 -keyfile ./radius.ca.key -cert ./radius.ca.cer -in ./radius.client.csr -out ./radius.client.cer

    Using configuration from /usr/local/ssl/openssl.cnf
    Check that the request matches the signature
    Signature ok
    Certificate Details:
            Serial Number: 2 (0x2)
            Validity
                Not Before: Oct 25 05:50:23 2020 GMT
                Not After : Oct 25 05:50:23 2021 GMT
            Subject:
                countryName               = CN
                stateOrProvinceName       = GD
                organizationName          = E
                organizationalUnitName    = EIS
                commonName                = MAN
                emailAddress              = email
            X509v3 extensions:
                X509v3 Basic Constraints: 
                    CA:FALSE
                Netscape Comment: 
                    OpenSSL Generated Certificate
                X509v3 Subject Key Identifier: 
                    03:87:E8:0B:87:9B:A1:89:A9:4D:73:90:6A:06:B6:6B:AD:E6:33:E1
                X509v3 Authority Key Identifier: 
                    keyid:9B:5D:7E:3F:59:6C:3E:6E:5C:25:4A:2C:6E:EB:70:DB:C9:3B:F9:C1

    Certificate is to be certified until Oct 25 05:50:23 2021 GMT (365 days)
    Sign the certificate? [y/n]:y
    failed to update database
    TXT_DB error number 2


# 修改证书权限
chmod 600 *.key *.cer