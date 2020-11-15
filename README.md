## Radius Server
Raidus Server is the system use to Authentication, Authorization, Accounting for WLAN user or PPPoE user.

Support authenticate method:

- [x] [CHAP](https://tools.ietf.org/search/rfc1994)

- [x] [PEAPv1: EAP-GTC](https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-05)

- [ ] [PEAPv0: EAP-MSCHAPv2](https://tools.ietf.org/html/draft-kamath-pppext-peapv0-00) TODO


## Installation and Usage
- Setup mysql

save [docker-compose.yml](https://github.com/zeroleo12345/restful_server/blob/master/docker-compose.yml) to another directory and start it.

`docker-compose -f docker-compose.yml up mysql`

- For authenticate

Build the docker image

`docker-compose build auth`

Run the docker container

`docker-compose up auth`

- For accouting

similiar with authenticate, but reaplce `auth` with `acct`


## Send authenticate and accounting request with simulator
- authenticate by CHAP

enter into authenticate container: `docker-compose exec auth bash`

run simulator in container:

```bash
$ cd tools/simulator/radius_test/auth/

$ radclient -D /app/tools/simulator/etc/dictionary -d /app/etc/dictionary 127.0.0.1:1812  auth  'testing123'  < /app/tools/simulator/radius_test/auth/chap.conf
```

- authenticate by EAP-GTC

enter into authenticate container: `docker-compose exec auth bash`

run simulator in container:

```bash
$ cd tools/simulator/eap_test/

$ eapol_test -c /app/tools/simulator/eap_test/eapol_test.conf.peap_v1_gtc -a 127.0.0.1 -p 1812 -s testing123 -r 0
```

- accounnting

enter into accounting container: `docker-compose exec acct bash`

run simulator in container:

```bash
$ cd tools/simulator/radius_test/acct/

$ radclient -D /app/tools/simulator/etc/dictionary -d /app/etc/dictionary 127.0.0.1:1813  acct  'testing123'  < /app/tools/simulator/radius_test/acct/i.conf
```
