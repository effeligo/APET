import signal
import re


NIC_MON = "mon0"
NIC_AP = "ap0"

TWIN_AP_ADDRESS = "10.0.1.1"

SSID = "ssid"
BSSID = "bssid"
CHANNEL = "ch"
CHANNEL_FREQ = "chfreq"
SIGSTREN = "sigstren"
DATARATE = "drate"
COUNTRY = "cn"
VENDOR = "vend"
STATIONS = "stations"

BPF_BEACON = "type mgt && subtype beacon"
BPF_DATA = "type data"

AP_CONF_TEMPLATE = "./config/hostapd_template.conf"
AP_CONF = "./config/hostapd.conf"
DNSMASQ_CONF_TEMPLATE = "./config/dnsmasq_template.conf"
DNSMASQ_CONF="./config/dnsmasq.conf"

GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[31m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

def print_banner():
    banner = """
     █████╗ ██████╗ ███████╗████████╗
    ██╔══██╗██╔══██╗██╔════╝╚══██╔══╝
    ███████║██████╔╝█████╗     ██║   
    ██╔══██║██╔═══╝ ██╔══╝     ██║   
    ██║  ██║██║     ███████╗   ██║   
    ╚═╝  ╚═╝╚═╝     ╚══════╝   ╚═╝    
    
    🦎  A P E T – Access Point Evil Twin
    """
    print(banner)

def signal_handler_factory(cleanup_coordinator):
    def signal_handler(sig, frame):
        if (sig == signal.SIGINT):
            print("[*] Caught SIGINT, cleaning up ...")
            cleanup_coordinator.cleanup_all()
    return signal_handler

def sp_error_handler(e):
    print(f"[!] Command failed during execution with return code {e.returncode}")
    print(f"    Command: {e.cmd}")
    print(f"    Output: {e.output}")

def clean_string(val):
    return re.sub(r"[^\x20-\x7E]", "", str(val)).strip()
