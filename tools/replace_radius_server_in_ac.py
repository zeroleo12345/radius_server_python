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
    undo rule 99
    rule 99 permit source {radius_server_ip} 0
quit

acl ipv6 number 2622
    undo rule 99
    rule 99 permit source {radius_server_ipv6}/128
quit

radius scheme eap_and_mac_radius_server
    primary authentication {radius_server_ipv6} test-profile user_probe
    primary accounting {radius_server_ip}
quit

radius dynamic-author server
    client ip {radius_server_ip} key simple testing123
    client ipv6 {radius_server_ipv6} key simple testing123
quit

save f


# MSR2600
TODO
"""

print("################# 执行的语句 ########################")
print(msg)
