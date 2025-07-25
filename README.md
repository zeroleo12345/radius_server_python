## Radius Server (Python)

This Raidus Server is writtten by Python, and is used to Authentication, Authorization, Accounting for WLAN user or PPPoE user.
Test authorization through supplicant on Windows10, Android 4.4.4 and iOS 13.

**Support authenticate method:**

- [x] [PAP](https://www.rfc-editor.org/rfc/rfc1334.html)

- [x] [CHAP](https://www.rfc-editor.org/rfc/rfc1994.html)

- [x] [MS-CHAPv2](https://www.rfc-editor.org/rfc/rfc2759.html)

- [x] [PEAPv0, PEAPv1: EAP-GTC](https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-05)

- [x] [PEAPv0, PEAPv1: EAP-MSCHAPv2](https://tools.ietf.org/html/draft-kamath-pppext-peapv0-00)

**Support Dynamic Authorization Extensions:**

- Disconnect Messages
- Change-of-Authorization (CoA) Messages


## Pull submodule src code
  ```
  git submodule update --init --recursive --remote --checkout   # pull
  ```


## Installation and Usage

- Setup database

  start pg:  `docker compose -f docker-compose.yml up pg`

  init database and table data with [mysql_insert.sql](https://github.com/zeroleo12345/radius_server_python/blob/master/data/db/mysql_insert.sql)

- For authenticate

  Build the docker image

  `docker compose build auth`

  Run the docker container

  `docker compose up auth`

- For accouting

  similiar with authenticate, but reaplce `auth` with `acct`


## Build

### build lib `libhostapd.so` from project `hostapd`

```bash
docker compose exec auth bash

cd third_party/hostapd-2.10/hostapd/
cat README.md
```


### build simulator `eapol_test` from project `wpa_supplicant`

```bash
docker compose exec auth bash

cd third_party/wpa_supplicant-2.10/wpa_supplicant/
cat README.md
```


### build simulator `radclient` from project `freeradius`
> `freeradius` not support `OpenSSL 3.0` well in debian `bookworm`

```bash
docker compose exec auth bash

cd third_party/freeradius-3.2.3/
cat README.md
```


## Send authenticate request with simulator

### Authenticate: `CHAP`

```bash
docker compose exec simulator bash

radclient -D /app/tools/simulator/etc/dictionary -d /app/etc/dictionary auth:1812  auth  'testing123'  < /app/tools/simulator/radius_test/auth/chap.conf
```


### Authenticate: `PAP`

```bash

docker compose exec simulator bash

# docker run --rm -it --network pppoe_system_network_name jumanjiman/radclient:latest \
radclient -D /app/tools/simulator/etc/dictionary -d /app/etc/dictionary auth:1812  auth  'testing123'  < /app/tools/simulator/radius_test/auth/pap.conf
```


### Authenticate: `MSCHAPv2`

1. `docker compose up -d auth_test`, listen on port 2812

2. Access Controller route traffic to 2812



### Authenticate: `EAP-GTC`

add `USE_GTC=1` in .env and restart docker container

enter into authenticate container: `docker compose exec auth bash`

run simulator in container directory `/app/tools/simulator/bin`:

```bash
eapol_test -c /app/tools/simulator/eap_test/eapol_test.conf.peapv1.gtc -a auth -p 1812 -s testing123 -r 0 -N 30:s:FF-FF-FF-FF-FF-FF -N 32:s:AC
```


### Authenticate: `EAP-MSCHAPv2`

remove `USE_GTC=0` in .env and restart docker container

enter into authenticate container: `docker compose exec auth bash`

run simulator in container directory `/app/tools/simulator/bin`:

```bash
./eapol_test -c /app/tools/simulator/eap_test/eapol_test.conf.peapv1.mschapv2 -a auth -p 1812 -s testing123 -r 0 -N 30:s:FF-FF-FF-FF-FF-FF -N 32:s:AC
```


## Send `Accounting` request with simulator

```bash
docker compose exec simulator bash

# i package
radclient -D /app/tools/simulator/etc/dictionary -d /app/etc/dictionary acct:1813  acct  'testing123'  < /app/tools/simulator/radius_test/acct/i.conf

# u package
radclient -D /app/tools/simulator/etc/dictionary -d /app/etc/dictionary acct:1813  acct  'testing123'  < /app/tools/simulator/radius_test/acct/u.conf

# t package
radclient -D /app/tools/simulator/etc/dictionary -d /app/etc/dictionary acct:1813  acct  'testing123'  < /app/tools/simulator/radius_test/acct/t.conf
```


## Send Dynamic Authorization Extensions request with simulator
  
### disconnect

run simulator in container directory `/app/tools/simulator/bin`:

```bash
docker compose exec simulator bash

radclient -D /app/tools/simulator/etc/dictionary -d /app/etc/dictionary dae:3799  disconnect  'testing123'  < /app/tools/simulator/radius_test/dae/disconnect.conf
```


## gdb core
```bash
gdb /root/.pyenv/shims/python -c core.1 
```


## gdb segmentation fault
```bash
ENTRYPOINT="tail -f /dev/null" docker compose up -d auth_test

apt-get install gdb

./bin/gdb.sh    # gdb python3

(gdb) run /app/src/processor/auth_processor.py

# wait for segfault ##

(gdb) backtrace

# stack trace of the c code
```
