# 🛡️ Intrusion Detection System (IDS) using Python and Scapy


## ⚡ Quick Start

```bash
git clone https://github.com/vansh2207/Intrusion-Detection-System-Python.git ( or https://github.com/chiranshu210/Intrusion-Detection-System-Python.git)
cd Intrusion-Detection-System-Python
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install scapy
python gui.py
```

⚠️ Run as **Administrator / sudo** for packet capture

---

## 📌 Overview

This project implements a **real-time Intrusion Detection System (IDS)** using Python and Scapy.  
It captures live network traffic and detects suspicious activities such as:

- Port scanning  
- High-frequency traffic  

Unlike traditional IDS systems, this project works on **live traffic (no dataset required)** and provides both CLI and GUI-based monitoring.

---

## 💡 Why This Project

- Demonstrates real-time cybersecurity concepts  
- Works without pre-recorded data  
- Includes GUI dashboard for visualization  
- Fully cross-platform (Windows, macOS, Linux)  

---

## 🚀 Features

- Real-time packet capture  
- Port scan detection  
- High-frequency traffic detection  
- CLI + GUI support  
- Smart interface detection  
- Color-coded logs:
  - 🔴 Alerts  
  - 🔵 Status  
  - ⚪ Traffic  
- IPv4 + IPv6 support  
- Cross-platform compatibility  

---

## 📁 Project Structure

```
IDS/
│── ids.py
│── gui.py
│── get_interfaces.py   ← ⭐ NEW (Windows helper)
│── suspicious_activity.log
│── README.md
│── REPORT.md
```

---

## ⚙️ Installation

### 1. Clone Repository

```bash
git clone https://github.com/vansh2207/Intrusion-Detection-System-Python.git
cd Intrusion-Detection-System-Python
```

---

### 2. Create Virtual Environment

```bash
python -m venv .venv
```

Activate:

**macOS / Linux**
```bash
source .venv/bin/activate
```

**Windows**
```bash
.venv\Scripts\activate
```

---

### 3. Install Dependencies

```bash
pip install scapy
```

---

## 🪟 Windows Setup (Important)

### Install Npcap:
👉 https://npcap.com/

✔ Enable **WinPcap compatibility mode**

---

## 🔍 Find Correct Network Interface (Windows Fix)

Windows interface names are confusing (`NPF_...`), so use this helper:

```bash
python get_interfaces.py
```

### Example Output:
```
\Device\NPF_{ABC123} -> 192.168.1.5
\Device\NPF_{XYZ456} -> 127.0.0.1
```

👉 Choose the one with your **real IP (192.168.x.x)**

❌ Avoid:
- 127.0.0.1 (loopback)  
- Virtual adapters  

---

## 🍎 macOS GUI Fix (if needed)

```bash
brew install python-tk@3.13
```

---

## 🖥️ Running the Project

---

### 🔹 List Interfaces

```bash
python ids.py --list-interfaces
```

---

### 🔹 Run IDS (CLI Mode)

**macOS / Linux**
```bash
sudo python ids.py --iface en0
```

**Windows**
```bash
python ids.py --iface "<interface>"
```

---

### 🔹 Run IDS (GUI Mode)

**macOS / Linux**
```bash
sudo -E python gui.py
```

**Windows**
```bash
python gui.py
```

---

## 📊 GUI Features

- Smart interface selection  
- Start / Stop IDS  
- Real-time logs  
- Scrollable console  
- Color-coded output  
- Live IDS monitoring  

---

## ⚙️ Detection Rules

| Type | Rule |
|------|------|
| Port Scan | 6 ports in 15s |
| High Frequency | 15 packets in 10s |
| Cooldown | 15s |

---

## 📄 Output

### CAPTURE
```
[time] CAPTURE | TCP | src -> dst
```

### STATUS
```
[time] STATUS | packets=... alerts=...
```

### ALERT
```
[time] ALERT | PORT_SCAN / HIGH_FREQUENCY
```

---

## 📁 Logs

Stored in:
```
suspicious_activity.log
```

---

## 🛠️ Troubleshooting

- **No packets captured**
  → Run as Administrator / sudo  

- **GUI not opening (macOS)**
  → Install tkinter  

- **No interfaces on Windows**
  → Install Npcap  

- **Confusing interface names**
  → Use `get_interfaces.py`  

---

## ⚠️ Limitations

- Requires admin privileges  
- Possible false positives  
- Local traffic only  
- No deep packet inspection  
- No ML-based detection  

---

## 🚀 Future Enhancements

- Machine learning detection  
- Graph visualization  
- Email/SMS alerts  
- Network-wide IDS  

---

## 🎯 Conclusion

This project demonstrates a **real-time IDS system** with CLI and GUI support.  

It detects suspicious activities using live traffic, making it practical, efficient, and ideal for academic demonstration.

---
