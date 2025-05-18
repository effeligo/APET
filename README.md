
# APET - Access Point Evil Twin

> **Prototype for Educational Use Only**  
> _Designed to explore the mechanics of deauthentication attack, Evil Twin attack, and wireless interface manipulation. This tool should only be used in **controlled environments** with **authorized devices and users**. **I am not responsible for any misuse or illegal activities** involving this software._

---
##  Description

**APET** is a Python-based prototype tool that automates Evil Twin attacks with a strong emphasis on **user-level phishing** and **network manipulation**. The goal is to **intercept wireless clients** and redirect them to **highly customized phishing pages** (that doesn't exist yet in the project 🪄) mimicking captive portals or known login screens.

This tool is designed to support **targeted social engineering exercises** and security awareness training. 

---
## Features

- 🛜 Wifi scanning to retrieve the nearby access points.
- 📡 Evil Twin attack support (APET requires two network interfaces to perform this attack: one for scanning/deauth, one to host the evil twin AP).
- 🎯 Deauthentication attack engine using raw 802.11 frame injection.
- 🌐 Flask-powered phishing server with captive portal interception and redirection.
- ✏️ Highly customizable phishing templates (targeted to specific environments or brands) At the moment it is published just one raw login page. 
- 🧪 Built with a learning-first approach, ideal for prototyping and experimentation. 

---
## Dependencies

Before running APET, ensure the following Python packages are installed:

```
pip install Flask scapy pyric tabulate yaspin

- Flask: http server management
- scapy: packet management (crafting, parsing, injecting etc.)
- pyric: amazing software that provides support during network card manipulation (https://github.com/wraith-wireless/PyRIC)
- tabulate: utility to provide cool terminal output
- yaspin: utility to provide cool terminal spinner (https://github.com/pavdmyt/yaspin)
```

Moreover, it is needed the installation of the following Linux packages:

```
- hostapd: access point emulation
- dnsmasq: station address leasing, dns traffic handling, network traffic logging etc.
```

**To run scan, deauth attack or evil twin attack APET requires to be executed with root permission.**

---
## Interface Requirements

APET **requires two different physical interfaces**:

- **Monitor Interface (e.g., `wlan1`)**: Used for scanning and sending deauthentication frames. 
- **AP Interface (e.g., `wlan0`)**: Used to spawn the rogue access point (via `hostapd`).

> 🛑 **None of the interfaces are destroyed or permanently altered**. Please consider that the tool will create a new virtual interface for each of those provided (mon0 and ap0). After APET exits, all network interfaces are restored to their original states.

---
## Phishing Page Redirection

A core strength of APET lies in its **automatic redirection of clients** (regardless of operating system) to a **custom phishing page** hosted by Flask. The phishing page is fully configurable and can mimic:

- Hotel Wi-Fi portals
- ISP login screens
- Social media login prompts
- Corporate SSO pages
- etc.

The goal is to trick the user into believing they must authenticate to access the Internet.

At the moment there is just one raw authentication page used for testing the application.


---
## Educational & Ethical Use

APET is designed **strictly for educational and research purposes**. Use it to:

- Understand Evil Twin mechanics
- Study wireless protocol behavior
- Develop custom phishing templates for red team simulations
- Test captive portal behavior across devices

---
## Future Improvements

This project is currently in a **prototype stage** and serves as a **learning experiment**.

**Planned improvements**:

- Code refactor to follow Python best practices and robust error handling;
- Template system for easy phishing page selection (implementation of the "--template" option logic that will be used to **download ready-to-use phishing templates** from an official GitHub repo);
- Integration with a Raspberry Pi for portable, field-ready deployments;
- Evaluate the feasibility of a single interface implementation for evil twin attack; 
- Logging system and session tracking.

---
## Contact & Contributions

This is a **learning-first** project, and contributions are welcome. Whether it's feature suggestions, bug fixes, or just feedback — feel free to open a pull request or issue.

---
## Usage example

You can find below an example usage to run the evil twin attack with APET. After the recon phase, the tool target the selected station with a deauth-attack and spawn the rogue ap named through the -tid param ("APET_AP" in this case).

Every http post in the phishing page generate a new log in the "captured_passwords.txt" file. 

```
$ sudo python apet.py -mi nic1 -ai nic2 --evil_twin -tid APET_AP


     █████╗ ██████╗ ███████╗████████╗
    ██╔══██╗██╔══██╗██╔════╝╚══██╔══╝
    ███████║██████╔╝█████╗     ██║   
    ██╔══██║██╔═══╝ ██╔══╝     ██║   
    ██║  ██║██║     ███████╗   ██║   
    ╚═╝  ╚═╝╚═╝     ╚══════╝   ╚═╝    
    
    🦎  A P E T – Access Point Evil Twin
    
⠼ Collecting APS
+---+-----------------+-------------------+-------+---------+-------------------+----------------+-----------+---------+--------+
|   |       ID        |       SSID        | BSSID | Channel | Channel-frequency | Signal-stregth | Data-rate | Country | Vendor |
+---+-----------------+-------------------+-------+---------+-------------------+----------------+-----------+---------+--------+
| 0 |     TEST-1      | 67:02:8a:b2:90:22 |  [6]  | [2437]  |        -67        |      1.0       |    IT     |  20722  |   []   |
| 1 |     TEST-2      | 26:3d:01:72:54:24 | [10]  | [2457]  |        -59        |      1.0       |    IT     |  20722  |   []   |
| 2 |     TEST-3      | c1:6f:59:3b:31:b1 | [11]  | [2462]  |        -67        |      1.0       |    IT     |  20722  |   []   |
+---+-----------------+-------------------+-------+---------+-------------------+----------------+-----------+---------+--------+
✅ Collecting APS

Please, select the target AP to start the stations collections: 2
⠼ Collecting Stations
+----+-----------------+-------------------+
| ID |      SSID       |     STATIONS      |
+----+-----------------+-------------------+
| 0  |     TEST-3      | 05:8d:70:81:b5:e3 |
+----+-----------------+-------------------+
✅ Collecting Stations

Please, select a valid station id to deauthenticate for evil twin attack: 0

[*] Starting deauthentication attack ...
[*] Starting the evil twin access point ...
[*] Starting hostapd ...
[*] Setting up dnsmasq ...
[*] Setting up the http server ...
 
```


