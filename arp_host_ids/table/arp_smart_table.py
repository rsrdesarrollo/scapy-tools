from scapy.layers.l2 import ARP
from scapy.arch import get_if_hwaddr
from scapy.config import conf as scapy_conf

_ARP_REQUEST = 0x01
_ARP_RESPONSE = 0x02

class ARPSmartTable(dict):

    def __init__(self, **kwargs):
        super(ARPSmartTable, self).__init__(**kwargs)
        self._on_entry_changes_listener = list()
        self._on_new_entry_listener = list()
        self._on_gratuitous_arp_listener = list()
        self._pending_request = set()

    def _trigger_new_entry(self, pkg, new):
        for p in self._on_new_entry_listener:
            p(pkg, new)

    def _trigger_entry_changes(self, pkg, old, new):
        for p in self._on_entry_changes_listener:
            p(pkg, old, new)

    def _trigger_gratuitous_arp(self, pkg):
        for p in self._on_gratuitous_arp_listener:
            p(pkg)

    def process_request(self, arp):
        assert isinstance(arp, ARP)
        assert arp.op == _ARP_REQUEST

        if arp.hwsrc == get_if_hwaddr(scapy_conf.iface):
            self._pending_request.add(arp.pdst)

    def process_response(self, arp):
        assert isinstance(arp, ARP)
        assert arp.op == _ARP_RESPONSE

        # This check can be bypassed if you don't filter request spoofed with your MAC
        if arp.psrc not in self._pending_request:
            # It seems we don't ask for this response
            self._trigger_gratuitous_arp(arp)
        else:
            self._pending_request.remove(arp.psrc)

        if arp.psrc in self:
            # We already know some MAC for this IP but is not the same
            if arp.hwsrc != self.get(arp.psrc):
                # The table entry sould change
                self._trigger_entry_changes(
                    arp,
                    (arp.psrc, self.get(arp.psrc)),
                    (arp.psrc, arp.hwsrc)
                )

                self[arp.psrc] = arp.hwsrc
        else:
            self._trigger_new_entry(arp, (arp.psrc, arp.hwsrc))
            self[arp.psrc] = arp.hwsrc

    def on_gratuitous_arp(self, cb):
        self._on_gratuitous_arp_listener.append(cb)

    def on_entry_changes(self, cb):
        self._on_entry_changes_listener.append(cb)

    def on_new_entry(self, cb):
        self._on_new_entry_listener.append(cb)