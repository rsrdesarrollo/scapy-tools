import logging
import sys, argparse

from scapy.sendrecv import sniff
from scapy.layers.l2 import ARP
from scapy.config import conf as scapy_conf

from table import ARPSmartTable

table = ARPSmartTable()

def arp_handler(pkg):
    arp = pkg[ARP]

    if arp.hwtype != 0x01:  # Avoid non Ethernet ARP
        return

    if arp.op == 0x01:      #ARP Request
        table.process_request(arp)
    elif arp.op == 0x02:    #ARP Response
        table.process_response(arp)

def on_arp_entry_changes(pkg, old, new):
    print "ARP Changes from",old,"to",new

def on_arp_new_entry(pkg, new):
    print "Leraning new ARP Entry",new

def on_gratuitous_arp(pkg):
    print "Received gratuitous ARP for",pkg.psrc,"on MAC",pkg.hwsrc

def main():
    parser = argparse.ArgumentParser(description="ARP spoofing detector")
    parser.add_argument('-f','--mac-file', help="file with static configured ARP entries")
    parser.add_argument('-i','--iface', help="Network interface", default='eth0')
    options = parser.parse_args(sys.argv[1:])

    scapy_conf.iface = options.iface

    table.on_entry_changes(on_arp_entry_changes)
    table.on_new_entry(on_arp_new_entry)
    table.on_gratuitous_arp(on_gratuitous_arp)

    sniff(iface=options.iface, prn=arp_handler, filter='arp')

    pass

if __name__ == '__main__':
    main()