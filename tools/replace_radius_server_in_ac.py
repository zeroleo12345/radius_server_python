#!/usr/bin/env python

import sys
if len(sys.argv) <= 2:
    print("[E] 需要2个参数: IPv4 和 IPv6")
    exit()
radius_server_ip = sys.argv[1]
radius_server_ipv6 = sys.argv[2]
print(f"\nRadius Server IP: {radius_server_ip}\n")
print(f"\nRadius Server IPv6: {radius_server_ipv6}\n")

msg = f"""
# MSR3600
acl number 2422
    undo rule 98
    rule 98 permit source {radius_server_ip} 0
    dis this
quit

acl ipv6 number 2622
    undo rule 98
    rule 98 permit source {radius_server_ipv6}/128
    dis this
quit

radius scheme eap_and_mac_radius_server
    primary authentication ipv6 {radius_server_ipv6} test-profile user_probe
    primary accounting {radius_server_ip}
    dis this
quit

radius dynamic-author server
    client ip {radius_server_ip} key simple testing123
    client ipv6 {radius_server_ipv6} key simple testing123
    dis this
quit

save f


# MSR2600
TODO
"""

print("################# 执行的语句 ########################")
print(msg)
