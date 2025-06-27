#!/usr/bin/env python3

import sys
import os
import re

# Add the current directory to the path so we can import fsyslog
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fsyslog import Fsyslog

def parse_fortigate_fixed(message):
    """Fixed version of parse_fortigate that handles quoted values properly"""
    message = str(message)
    d = {}
    start_str = '- - - -'
    pos = message.find(start_str)
    if pos >= 0:
        key_values = message[pos + len(start_str):].strip()
        # Use regex to properly handle quoted values and spaces
        pattern = r'(\w+)\s*=\s*("([^"]*)"|([^\s]+))'
        matches = re.findall(pattern, key_values)
        for match in matches:
            key = match[0]
            value = match[2] if match[2] else match[3]
            d[key] = value
    else:
        return d
    return d

def test_parse_fortigate():
    # Both syslog messages to test
    messages = [
        '<189>1 2025-06-04T15:29:06Z FortiGate-1800F-GUA - - - - eventtime=1749050946187327342 tz="-0600" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=2803:1040:1802:3b4b:7ca4:6cd6:e0de:714d srcport=58769 srcintf="port36" srcintfrole="wan" dstip=2803:e880:8111:1b:: dstport=53 dstintf="ZONA-DNS" dstintfrole="lan" sessionid=395601599 proto=17 action="accept" policyid=430 policytype="policy" poluuid="bd93d5a2-0bdf-51ef-d488-97112a346de5" policyname="SGACTNICASAIPV6" srccountry="Nicaragua" dstcountry="Guatemala" service="DNS" trandisp="noop" duration=30 sentbyte=92 rcvdbyte=197 sentpkt=1 rcvdpkt=1 appcat="unscanned" dsthwvendor="HP" masterdstmac="94:18:82:68:22:35" dstmac="94:18:82:68:22:35" dstserver=1',
        b'<188>1 2025-06-05T18:12:15Z FWFGSGECGYEDCCD01 - - - - eventtime=1749147134399466940 tz="-0500" logid="1501054803" type="utm" subtype="dns" eventtype="dns-response" level="warning" vd="root" policyid=857 poluuid="79fee2fc-957c-51ee-1f1c-a197944af7b9" policytype="policy" sessionid=884067159 srcip=45.225.47.204 srcport=36056 srccountry="Ecuador" srcintf="INTERNET-VRF" srcintfrole="wan" dstip=177.234.200.3 dstport=53 dstcountry="Ecuador" dstintf="port21" dstintfrole="undefined" proto=17 profile="dns_seguro" srcmac="6c:13:d5:b5:09:50" xid=29238 qname="vddgcoud02.gd34fdldh.xyz" qtype="A" qtypeval=1 qclass="IN" ipaddr="208.91.112.55" msg="Domain belongs to a denied category in policy" action="redirect" cat=26 catdesc="Malicious Websites"'
    ]
    
    for idx, message in enumerate(messages, 1):
        print(f"\n--- Test {idx}: ---")
        print(f"Input message: {message}")
        print("-" * 80)
        result = parse_fortigate_fixed(message)
        print("Parsed result:")
        print("-" * 80)
        for key, value in result.items():
            print(f"{key}: {value}")
        print("-" * 80)
        print(f"Total fields extracted: {len(result)}")

if __name__ == "__main__":
    test_parse_fortigate() 