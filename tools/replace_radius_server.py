#!/usr/bin/env python

import sys
radius_server_ip = sys.argv[1]
print(f"\nRadius Server IP: {radius_server_ip}\n")

msg = f"""
radius dynamic-author client trusted ip {radius_server_ip}
acl number 2001
 undo rule 50
 rule 50 permit source {radius_server_ip} 0
quit
acl number 3001
 undo rule 50
 rule 50 permit tcp source {radius_server_ip} 0 destination-port eq telnet
quit
radius scheme eap_radius_scheme
 primary authentication {radius_server_ip} probe username user_probe interval 12
 primary accounting {radius_server_ip} probe username user_probe interval 12
quit
radius scheme eapoff_radius_scheme
 primary authentication {radius_server_ip} probe username user_probe interval 12
 primary accounting {radius_server_ip} probe username user_probe interval 12
quit
save f
"""

print("################# 执行的语句 ########################")
print(msg)
