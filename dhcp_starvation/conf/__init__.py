from scapy.arch import get_if_hwaddr

iface = 'eth0'
dtimer = 1
dparal = 1
if_mac = get_if_hwaddr(iface)
hostname = 'android-'
spoof=False