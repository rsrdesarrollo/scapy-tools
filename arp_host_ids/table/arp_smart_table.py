from scapy.layers.l2 import ARP

class ARPSmartTable(object):
    def __init__(self):
        self.on_entry_changes_listener = list()
        self.on_new_entry_listener = list()
        self.arp_table = dict()

    def process_request(self, arp):
        assert isinstance(arp, ARP)

    def process_response(self, arp):
        assert isinstance(arp, ARP)

    def on_entry_changes(self, cb):
        self.on_entry_changes_listener.append(cb)

    def on_new_entry(self, cb):
        self.on_new_entry_listener.append(cb)