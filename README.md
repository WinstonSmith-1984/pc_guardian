# LOTL-LAN 🦀 (v1.9.57)

<p align="left">
Hi, I'm Derek, a cybersecurity analyst. 🏅 I specialize in developing **Living off the Land (LOTL)** detection and threat intelligence software for internal networks.
</p>

### 🛡️ Contact: [![Encrypted Signal](https://img.shields.io/badge/Signal-End--to--End%20Encrypted-blue?style=flat-square&logo=signal&logoColor=white)](https://signal.me/#eu/89vdbTjG9CIOm4P9fsQh11rpyLnOKqhPyLRuyZFcipeOx2P_cyFIHLYrEVWteCPV)

---

**LOTL-LAN** (Living Off The Land - Local Area Network) is a real-time internal traffic sniffer and host analyst tool. Unlike traditional firewalls that monitor the perimeter, LOTL-LAN focuses on **East-West traffic**, identifying suspicious lateral movement, protocol abuse, and reconnaissance patterns within your internal network.

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)
![License](https://img.shields.io/badge/License-GPL--3.0-blue?style=for-the-badge)

---

## 🚀 Key Features

* **Passive Sniffer Engine**: Utilizes `PyShark` (TShark) to perform live packet capture across any system interface.
* **Lateral Movement Detection**: Automatically flags internal connections (192.168.x.x) to identify potential pivoting or unauthorized internal scans.
* **Protocol Intelligence Engine**: Specifically monitors for protocols used in "Living off the Land" attacks, such as **NBNS**, **LLMNR**, and **ARP**.
* **Visual Telemetry**: Real-time breakdown of network traffic types and dynamic RAG (Red-Amber-Green) security status alerts.

---

## 📦 Installation & Setup

### Option A: Standalone Executable (Easy / Recommended)
No Python installation is required. This is the fastest way to get started.

1. **Prerequisite**: You must have **TShark** (Wireshark) installed on your system.
2. Go to the **[Releases](https://github.com/WinstonSmith-1984/LIVING-OFF-THE-LAND-/releases/latest)** page.
3. Download the binary for your OS (e.g., `lotl-lan-windows.exe` or `lotl-lan-linux`).
4. Run the file. (See **Security Notes** below regarding permissions).

### Option B: Manual Install (For Developers)
1. Ensure you have **Python 3.10+** and **TShark** installed.
2. Clone & Install:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/lotl-lan.git](https://github.com/YOUR_USERNAME/lotl-lan.git)
   cd lotl-lan
   pip install streamlit pandas plotly pyshark
   streamlit run main.py
