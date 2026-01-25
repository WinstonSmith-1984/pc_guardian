```markdown
# # LOTL-LAN 🦀 (v1.9.57)

<p align="left">
  <a href="https://www.credly.com/badges/270c2310-e8c5-4216-b474-f24ff2d9cec4/public_url" target="_blank">
    <img src="https://images.credly.com/images/a74dc347-5429-4fc2-8878-74df7c213866/ibm-cybersecurity-analyst-professional-certificate.png" width="130" height="130" alt="IBM Cybersecurity Analyst Professional Certificate">
  </a>
</p>

**LOTL-LAN** is a tactical internal network monitoring and threat intelligence suite designed to detect **Living off the Land** (LOTL) attack vectors within a Local Area Network. 

By focusing on **East-West traffic** and protocol-specific anomalies (LLMNR, NBNS, MDNS, ARP), LOTL-LAN provides security analysts with real-time visibility into lateral movement and internal poisoning attempts.

---

## 🚀 Key Features

* **Active Threat Intelligence**: Automatically analyzes protocol frequency for lateral pivot patterns and escalates alerts to the System Security Status window.
* **East-West Threat Window**: A dedicated, scrollable log that deduplicates and tracks unique internal connection strings.
* **Protocol Decoder**: Deep-dive intelligence on discovery protocols used in NTLM relay and spoofing attacks.
* **Tactical HUD**: 
    * **5s Stabilized Refresh**: Zero-flicker UI for high-stress monitoring environments.
    * **CSV Export**: One-click forensic documentation of all discovered threats for incident response.
    * **Security Status Grid**: Real-time health monitoring of ARP, Scanning, and Host-based decoys.

---

## 🔧 Technical Architecture & Requirements

### Security Analyst Stack
* **Python 3.9+**: Core engine for asynchronous packet analysis.
* **PyShark**: TShark wrapper used for deep packet inspection (DPI).
* **Streamlit & Plotly**: Used to create a high-fidelity Tactical HUD for real-time monitoring.
* **Pandas**: Manages data frames for forensic CSV processing.

### System Requirements
* **TShark (Wireshark)**: Must be installed on the host system.
* **Elevated Privileges**: Root/Admin access is required to place the network interface into promiscuous mode for packet capture.

---

## 📦 Installation & Usage

### 1. Install Network Dependencies
```bash
sudo apt-get install tshark

```

### 2. Initialize the Suite

Ensure you are running with administrative privileges to allow packet capture:

```bash
streamlit run lotl_lan.py

```

---

## 📬 Contact & Connect

If you have questions regarding the technical architecture of this suite or wish to discuss security analyst opportunities:

> **"Visibility is the first step toward defense."**

```

```
