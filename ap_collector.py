from tabulate import tabulate as tab

SSID = "ssid"
BSSID = "bssid"
CHANNEL = "ch"
CHANNEL_FREQ = "chfreq"
SIGSTREN = "sigstren"
DATARATE = "drate"
COUNTRY = "cn"
VENDOR = "vend"


class AP_Collector:
    def __init__(self):
        self.apc = {}

    def _build_ap_el(self, ssid, bssid, ch, chfreq, sigstren, drate, cn, vend):
        return {
            SSID: ssid,
            BSSID: bssid,
            CHANNEL: [ch],
            CHANNEL_FREQ: [chfreq],
            SIGSTREN: sigstren,
            DATARATE: drate,
            COUNTRY: cn,
            VENDOR: vend 
        }

    def update(self, ssid, bssid, ch, chfreq, sigstren, drate, cn, vend):
        if ssid not in self.apc:
            self.apc[ssid] = self._build_ap_el(ssid, bssid, ch, chfreq, sigstren, drate, cn, vend)
        else:
            self.apc[ssid][BSSID] = bssid
            if ch:
                nl = self.apc[ssid][CHANNEL] + [ch] 
                self.apc[ssid][CHANNEL] = list(set(nl))
            if chfreq:
                nl = self.apc[ssid][CHANNEL_FREQ] + [chfreq] 
                self.apc[ssid][CHANNEL_FREQ] = list(set(nl))
            self.apc[ssid][SIGSTREN] = sigstren
            self.apc[ssid][DATARATE] = drate
            self.apc[ssid][COUNTRY] = cn
            self.apc[ssid][VENDOR] = vend

    def pprint(self):
        headers = ["SSID", "BSSID", "Channel", "Channel-frequency", "Signal-stregth", "Data-rate", "Country", "Vendor"]
        rows = self.apc.values()
        table = [list(v.values()) for v in rows]
        print(tab(table, headers=headers))