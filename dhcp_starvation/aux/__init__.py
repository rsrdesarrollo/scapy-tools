from scapy.utils import str2mac
from scapy.layers.dhcp import BOOTP, DHCP


def _create_dhcp_options_dict(pkg):
    ret = dict(map(lambda o: ((o, True), o)[isinstance(o, tuple)], pkg[DHCP].options))
    ret['chaddr'] = str2mac(pkg[BOOTP].chaddr[:6])
    ret['yiaddr'] = pkg[BOOTP].yiaddr
    ret['xid'] = pkg[BOOTP].xid

    return ret