import scapy.all as scapy
import util
from tabulate import tabulate as tab


class APCollector:
    def __init__(self, nicm):
        self.nicm = nicm
        self.current_channel = 1
        self.apc = {}
        self.ap_counter = 0

    def _build_ap_el(self, ssid, bssid, ch, chfreq, sigstren, drate, cn, vend):
        return {
            util.SSID: ssid,
            util.BSSID: bssid,
            util.CHANNEL: [ch],
            util.CHANNEL_FREQ: [chfreq],
            util.SIGSTREN: sigstren,
            util.DATARATE: drate,
            util.COUNTRY: cn,
            util.VENDOR: vend, 
            util.STATIONS: []
        }

    def aps_count(self):
        return len(self.apc)
    
    def st_count(self, ap_id):
        return len(self.apc[ap_id][util.STATIONS])

    def get_ap_data(self, ap_id):
        return self.apc[ap_id]
        
    def sniff_beacon_frame(self):
        done=False
        while not done:
            self.nicm.set_channel(self.current_channel, util.NIC_MON)
            scapy.sniff(filter=util.BPF_BEACON, iface=util.NIC_MON, count=0, timeout=1, prn=self.beacon_frame_manager())
            self.current_channel+=1
            if self.current_channel == 13:
                self.current_channel = 1
                done = True
        self.pprint_aps()  
    
    def beacon_frame_manager(self):
        def handle_beacon_frame(pkt):
            ssid="None"
            bssid="None"
            channel="None"
            chfreq="None"
            sigstren="None"
            drate="None"
            country="None"
            vendor="None"
    
            for payload in pkt.iterpayloads():
                if payload.name == "RadioTap":
                    drate = payload.getfieldval("Rate")
                    chfreq = payload.getfieldval("ChannelFrequency")
                    sigstren = payload.getfieldval("dBm_AntSignal")
                elif payload.name == "802.11":
                    bssid = payload.getfieldval("addr3")
                elif payload.name == "802.11 Information Element":
                    if payload.getfieldval("ID") == 0:
                        ssid = payload.getfieldval("info").decode('utf-8')
                elif payload.name == "802.11 DSSS Parameter Set":
                    channel=payload.getfieldval("channel")
                elif payload.name == "802.11 Country":
                    country=payload.getfieldval("country_string").decode('utf-8')
                elif payload.name == "802.11 Vendor Specific":
                    vendor=payload.getfieldval("oui")            
    
            self.update(ssid, bssid, channel, chfreq, sigstren, drate, country, vendor)
    
        return handle_beacon_frame
      
    def sniff_data_frame(self, ap_id):
        scapy.sniff(filter=util.BPF_DATA, iface=util.NIC_MON, monitor=True, count=0, timeout=10, prn=self.data_frame_manager(ap_id))
        self.pprint_stations(ap_id)

    def data_frame_manager(self, ap_id):
        def handle_data_frame(pkt):
            for payload in pkt.iterpayloads():
                if payload.name == "802.11":
                    ap_mac = payload.getfieldval("addr1")
                    station_mac = payload.getfieldval("addr2")
                    if ap_mac == self.apc[ap_id][util.BSSID] and station_mac not in self.apc[ap_id][util.STATIONS]:
                        self.apc[ap_id][util.STATIONS].append(station_mac)
                        break
        return handle_data_frame

    def update(self, ssid, bssid, ch, chfreq, sigstren, drate, cn, vend):
        aps_tmp = [(ap_id, ap_specs[util.SSID]) for ap_id, ap_specs in self.apc.items()]
        ap_id = next((id for id, _ssid in aps_tmp if ssid == _ssid), None)
        if ap_id is None:
            self.apc[self.ap_counter] = self._build_ap_el(ssid, bssid, ch, chfreq, sigstren, drate, cn, vend)
            self.ap_counter+=1
        else:
            self.apc[ap_id][util.BSSID] = bssid
            if ch:
                nl = self.apc[ap_id][util.CHANNEL] + [ch] 
                self.apc[ap_id][util.CHANNEL] = list(set(nl))
            if chfreq:
                nl = self.apc[ap_id][util.CHANNEL_FREQ] + [chfreq] 
                self.apc[ap_id][util.CHANNEL_FREQ] = list(set(nl))
            self.apc[ap_id][util.SIGSTREN] = sigstren
            self.apc[ap_id][util.DATARATE] = drate
            self.apc[ap_id][util.COUNTRY] = cn
            self.apc[ap_id][util.VENDOR] = vend

    
    def pprint_aps(self):
        print()
        headers = ["ID", "SSID", "BSSID", "Channel", "Channel-frequency", "Signal-stregth", "Data-rate", "Country", "Vendor"]
        table = []
        for ap_id, ap_specs in self.apc.items():
            table.append([ap_id] + [util.clean_string(val) for val in ap_specs.values()])
        print(tab(table, headers=headers, tablefmt="pretty"))

    def pprint_stations(self, ap_id):
        print()
        headers = ["ID", "SSID", "STATIONS"]
        table = []
        station_counter = 0
        ssid = self.apc[ap_id][util.SSID]
        for el in self.apc[ap_id][util.STATIONS]:
            table.append([str(station_counter), ssid, util.clean_string(el)])
            station_counter+=1
        print(tab(table, headers=headers, tablefmt="pretty"))
