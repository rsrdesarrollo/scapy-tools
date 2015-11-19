import conf

from scapy.utils import mac2str, str2mac
from scapy.volatile import RandString
from scapy.layers.l2 import Ether
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP

def _build_dhcp_request_from_offer(options):
    request_opt = [('message-type', 'request'),
                   ('requested_addr', options['yiaddr']),
                   ('server_id', options['server_id']),
                   ('hostname', conf.hostname + str(RandString(16, '0123456789abcdef'))),
                   ('param_req_list', b'x01x1c 2x03x0fx06x77x0cx2cx2fx1ax79x2a'),
                   'end'
                   ]

    req = Ether(src=conf.if_mac, dst="ff:ff:ff:ff:ff:ff") / \
          IP(src="0.0.0.0", dst="255.255.255.255") / \
          UDP(sport=68, dport=67) / \
          BOOTP(xid=options['xid'], chaddr=mac2str(options['chaddr'])) / \
          DHCP(options=request_opt)

    return req
