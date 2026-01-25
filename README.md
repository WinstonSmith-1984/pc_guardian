# LOTL-LAN 🦀 (v1.9.57)

<p align="left">
Hi , I'm Derek, a cybersecurity analyst. <a href="https://www.credly.com/badges/270c2310-e8c5-4216-b474-f24ff2d9cec4/public_url" target="_blank"> 🏅</a>  Specialising in developing **Living off the Land (LOTL)** detection and internal network threat intelligence software.
</p>

Hi, I'm Derek, a cybersecurity analyst. 🏅 

Specialising in developing **Living off the Land (LOTL)** detection and internal network threat intelligence software.

---

### 🛡️ Secure Communication
[![Encrypted Signal](https://img.shields.io/badge/Signal-End--to--End%20Encrypted-blue?style=flat-square&logo=signal&logoColor=white)](https://signal.me/#eu/89vdbTjG9CIOm4P9fsQh11rpyLnOKqhPyLRuyZFcipeOx2P_cyFIHLYrEVWteCPV)
# 🦀 

**LOTL-LAN** (Living Off The Land - Local Area Network) is a real-time internal traffic sniffer and host analyst tool. Unlike traditional firewalls that monitor the perimeter, LOTL-LAN focuses on **East-West traffic**, identifying suspicious lateral movement, protocol abuse, and reconnaissance patterns within your internal network.

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)
![License](https://img.shields.io/badge/License-GPL--3.0-blue?style=for-the-badge)

---

## 🚀 Key Features

* **Passive Sniffer Engine**: Utilizes `PyShark` (TShark) to perform live packet capture across any system interface (`eth0`, `wlan0`, etc.).
* **Lateral Movement Detection**: Automatically flags internal connections (192.168.x.x) to identify potential pivoting or unauthorized internal scans.
* **Active Threat Tagging**: Allows analysts to manually "tag" suspicious connections to generate deep-dive intelligence reports.
* **Protocol Intelligence Engine**: Specifically monitors for protocols used in "Living off the Land" attacks, such as **NBNS**, **LLMNR**, and **ARP**.
* **Visual Telemetry**:
    * **East-West Threat Window**: A dedicated, high-visibility log for internal-to-internal alerts.
    * **Dynamic Security Status**: Visual RAG (Red-Amber-Green) alerts that flip from "Secure" to "Alert" when active threats are tagged.
    * **Protocol Distribution**: Real-time breakdown of network traffic types using Plotly.


---

## 🛠️ Installation

### 1. Requirements
You must have **TShark** (Wireshark's command-line tool) installed on your system for the sniffer engine to function:
* **Linux**: `sudo apt install tshark`
* **macOS**: `brew install wireshark`

### 2. Clone & Install
```bash
git clone [https://github.com/YOUR_USERNAME/lotl-lan.git](https://github.com/YOUR_USERNAME/lotl-lan.git)
cd lotl-lan
pip install streamlit pyshark pandas plotly
