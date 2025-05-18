import util
import pyric.pyw as pyw


class NicManager:

    def __init__(self):
        self.default_nics = []
        self.custom_nics = []
    
    def setup_mon_nic(self, default_mon_nic):
        if pyw.isinterface(default_mon_nic):
            default_mon_card = pyw.getcard(default_mon_nic)
            mon0 = pyw.devadd(default_mon_card, util.NIC_MON, "monitor")
            pyw.down(default_mon_card)
            pyw.up(mon0)
            self.custom_nics.append(mon0)
            self.default_nics.append(default_mon_card)
        
    def setup_ap_nic(self, default_ap_nic):
        if pyw.isinterface(default_ap_nic):
            default_ap_card = pyw.getcard(default_ap_nic)
            ap0 = pyw.devadd(default_ap_card, util.NIC_AP, "managed")
            pyw.down(default_ap_card)
            pyw.up(ap0)
            self.custom_nics.append(ap0)
            self.default_nics.append(default_ap_card)

    def cleanup(self):
        current_nics = pyw.winterfaces()
        for nic in self.custom_nics:
            if nic.dev in current_nics:
                pyw.devdel(nic)
        for nic in self.default_nics:
            pyw.up(nic)
            
    def set_channel(self, channel, nic):
        for el in self.default_nics:
            pyw.down(el)
        card = pyw.getcard(nic)
        pyw.chset(card, channel, None)

    def set_address(self, nic):
        card = pyw.getcard(nic)
        pyw.inetset(card, util.TWIN_AP_ADDRESS)

