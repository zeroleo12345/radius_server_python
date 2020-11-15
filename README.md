## Radius Server
Raidus Server is the system use to Authentication, Authorization, Accounting for WLAN user or PPPoE user.

Support authenticate method:
    - [x] [CHAP](https://tools.ietf.org/search/rfc1994)
    - [x] [PEAPv1: EAP-GTC](https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-05)
    - [] TODO [PEAPv0: EAP-MSCHAPv2](https://tools.ietf.org/html/draft-kamath-pppext-peapv0-00)


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



## Debug with simulator
- authenticate by CHAP
enter into container: `docker-compose exec auth bash`
run simulator in container:
```bash
$ cd tools/simulator/radius_test/auth/
$ sh run.sh
```

- authenticate by EAP-GTC
enter into container: `docker-compose exec auth bash`
run simulator in container:
```bash
$ cd tools/simulator/eap_test/
$ sh run.sh
```

