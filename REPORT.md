# Project Report: Intrusion Detection System (IDS) using Python with GUI

## GitHub Link

https://github.com/chiranshu210/Intrusion-Detection-System-Python.git  
https://github.com/vansh2207/Intrusion-Detection-System-Python.git  

---

## 1. Problem Statement

The aim of this project is to design and implement a real-time Intrusion Detection System (IDS) using Python and Scapy. The system captures live network packets from a selected interface and identifies suspicious activity based on predefined behavioral rules.

The IDS focuses on detecting:

- Port scanning attacks  
- High-frequency traffic anomalies  

Upon detection, the system generates alerts in real time and logs the suspicious activity for further analysis.

Unlike traditional IDS implementations that rely on pre-recorded datasets, this system operates entirely on **live network traffic**, making it more practical and suitable for real-world demonstrations.

---

## 2. Objectives

- To monitor live network traffic in real time  
- To detect abnormal behavior using threshold-based techniques  
- To provide immediate alerting and logging mechanisms  
- To build an intuitive, real-time GUI dashboard for visualization  
- To ensure cross-platform compatibility (macOS, Linux, Windows)  
- To improve usability on Windows through a helper interface-detection script  

---

## 3. Tools and Technologies Used

- Python 3  
- Scapy (for packet sniffing and analysis)  
- Tkinter (for GUI development)  
- Npcap (required on Windows for packet capture)  
- Platform module (for OS-neutral execution)  

---

## 4. Project Files

- `ids.py` – Core IDS logic and detection engine  
- `gui.py` – Graphical User Interface  
- `get_interfaces.py` – Helper script for identifying correct interface (Windows usability fix)  
- `suspicious_activity.log` – Log file storing alerts  
- `README.md` – Usage instructions  
- `REPORT.md` – Project documentation  

---

## 5. System Architecture

The system consists of three main components:

### 1. Packet Capture Engine (Scapy)
- Captures live packets from the selected interface  
- Supports both IPv4 and IPv6 traffic  
- Performs real-time packet sniffing  

### 2. Detection Engine
- Applies rule-based detection logic  
- Uses a **time-based sliding window algorithm**  
- Tracks request frequency and port access patterns  

### 3. User Interface Layer
- CLI for raw monitoring  
- GUI dashboard for interactive visualization  
- Displays real-time logs and alerts  

---

## 6. Working of the IDS

The IDS continuously monitors network traffic using Scapy’s sniffing functionality. It processes packets in real time and extracts information such as source IP, destination IP, ports, and protocol.

### Execution Flow:

1. Capture packets from selected interface  
2. Filter traffic related to the local device  
3. Extract packet details  
4. Apply detection rules  
5. Generate alerts if thresholds are exceeded  
6. Display output in CLI/GUI  
7. Store alerts in log file  

The system uses a **time-based sliding window approach**, ensuring only recent packet activity is analyzed for efficient real-time detection.

---

## 7. Detection Logic

### 7.1 Port Scan Detection

A port scan is detected when a source IP attempts connections to multiple destination ports within a short time.

**Default Rule:**
- 6 unique ports in 15 seconds  

This indicates potential reconnaissance activity.

---

### 7.2 High-Frequency Detection

High-frequency traffic is detected when a source IP sends an unusually large number of packets within a short duration.

**Default Rule:**
- 15 packets in 10 seconds  

This helps detect abnormal traffic bursts or flooding behavior.

---

## 8. GUI Implementation

A Graphical User Interface (GUI) is developed using Tkinter to enhance usability and visualization.

### GUI Features:

- Smart interface detection with readable labels  
- Dropdown-based interface selection  
- Start / Stop IDS controls  
- Real-time scrolling output window  
- Color-coded logs:
  - 🔴 Red → Alerts  
  - 🔵 Blue → Status  
  - ⚪ Gray → Normal traffic  
- Live streaming of IDS output  

### GUI Working:

- The GUI launches `ids.py` as a subprocess  
- Captures real-time output  
- Displays logs dynamically  
- Applies color tagging for better readability  

This provides an **intuitive real-time monitoring dashboard**.

---

## 9. Cross-Platform Implementation

The system is designed to work across:

- macOS  
- Linux  
- Windows  

### Key Features:

- OS detection using `platform` module  
- Automatic inclusion of `sudo` for Unix systems  
- Windows-compatible execution without `sudo`  
- Support for Npcap interfaces  

---

## 10. Windows Interface Selection Enhancement

Windows network interfaces often appear with complex names (e.g., `NPF_*`), making selection difficult.

To solve this, a helper script (`get_interfaces.py`) is introduced.

### Functionality:

- Lists all available interfaces  
- Displays associated IP addresses  
- Helps identify the correct interface quickly  

### Example:

```
\Device\NPF_{ABC123} -> 192.168.1.5
```

Users should select the interface with a valid IP (e.g., 192.168.x.x), avoiding loopback or virtual adapters.

---

## 11. Alert and Logging System

When suspicious activity is detected:

- Alert is displayed in CLI/GUI  
- Alert is written to `suspicious_activity.log`  

### Example:

```
[YYYY-MM-DD HH:MM:SS] ALERT | PORT_SCAN | Direction: INBOUND | Source IP: X.X.X.X
[YYYY-MM-DD HH:MM:SS] ALERT | HIGH_FREQUENCY | Direction: OUTBOUND | Source IP: X.X.X.X
```

---

## 12. How to Run the Project

### View Interfaces
```
python ids.py --list-interfaces
```

### Run CLI
```
sudo python ids.py --iface en0        (macOS/Linux)
python ids.py --iface "<interface>"   (Windows)
```

### Run GUI
```
sudo -E python gui.py   (macOS/Linux)
python gui.py           (Windows)
```

### Windows Setup

- Install Npcap  
- Run terminal as Administrator  
- Use `get_interfaces.py` to find the correct interface  

---

## 13. Expected Output

The system generates:

- CAPTURE → Live packet activity  
- STATUS → Packet statistics  
- ALERT → Suspicious activity  

---

## 14. Advantages

- Real-time detection  
- Works on **live traffic (no dataset required)**  
- Lightweight and efficient  
- Cross-platform compatibility  
- GUI + CLI flexibility  
- Improved Windows usability  

---

## 15. Limitations

- Requires administrator/root privileges  
- May produce false positives  
- Monitors only local system traffic  
- No deep packet inspection for encrypted traffic  
- Does not currently implement machine learning-based detection  

---

## 16. Future Enhancements

- Machine learning-based detection  
- Network-wide monitoring  
- Advanced GUI with graphical analytics  
- Email/SMS alert integration  
- Attack classification system  

---

## 17. Conclusion

This project successfully implements a real-time Intrusion Detection System using Python and Scapy.

It captures live network traffic, detects suspicious behavior such as port scanning and high-frequency activity, and generates alerts in real time.

The addition of a GUI dashboard, cross-platform compatibility, and a Windows interface helper script makes the system highly practical, user-friendly, and suitable for real-world demonstrations.

This project provides a strong foundation for advanced IDS development.

---

