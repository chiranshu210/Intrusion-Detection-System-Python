import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import subprocess
import sys
import platform
from scapy.all import get_if_list, get_if_addr, conf

class IDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IDS Dashboard")
        self.root.geometry("1100x650")
        self.root.configure(bg="#1e1e2e")

        # ---------- STYLE ----------
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Header.TLabel",
                        font=("Arial", 18, "bold"),
                        background="#0f172a",
                        foreground="white")

        style.configure("Card.TFrame",
                        background="#2a2a3c")

        style.configure("TButton",
                        font=("Arial", 10, "bold"),
                        padding=6)

        # ---------- HEADER ----------
        header = ttk.Label(root,
                           text="Intrusion Detection System Dashboard",
                           style="Header.TLabel",
                           anchor="center")
        header.pack(fill="x", pady=5)

        # ---------- TOP PANEL ----------
        top_frame = ttk.Frame(root, style="Card.TFrame", padding=10)
        top_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(top_frame, text="Select Interface:",
                  background="#2a2a3c", foreground="white").grid(row=0, column=0, padx=5)

        self.iface_var = tk.StringVar()
        self.iface_map = {}

        self.iface_dropdown = ttk.Combobox(
            top_frame,
            textvariable=self.iface_var,
            width=40,
            state="readonly"
        )
        self.iface_dropdown['values'] = self.get_interfaces()
        self.iface_dropdown.grid(row=0, column=1, padx=5)

        # Auto-select active interface
        default = conf.iface
        for label, real in self.iface_map.items():
            if real == default:
                self.iface_dropdown.set(label)
                break
        else:
            if self.iface_dropdown['values']:
                self.iface_dropdown.current(0)

        # Buttons
        self.start_btn = ttk.Button(top_frame, text="▶ Start IDS", command=self.start_ids)
        self.start_btn.grid(row=0, column=2, padx=10)

        self.stop_btn = ttk.Button(top_frame, text="⏹ Stop IDS", command=self.stop_ids)
        self.stop_btn.grid(row=0, column=3, padx=10)

        # ---------- STATS PANEL ----------
        stats_frame = ttk.Frame(root, style="Card.TFrame", padding=10)
        stats_frame.pack(fill="x", padx=10, pady=5)

        self.alert_label = self.create_stat(stats_frame, "Alerts", 0)
        self.packet_label = self.create_stat(stats_frame, "Packets", 1)
        self.status_label = self.create_stat(stats_frame, "Status", 2)

        # ---------- OUTPUT ----------
        self.output = scrolledtext.ScrolledText(
            root,
            wrap=tk.WORD,
            font=("Courier", 10),
            bg="#0f172a",
            fg="white",
            insertbackground="white"
        )
        self.output.pack(fill="both", expand=True, padx=10, pady=10)

        # Colors
        self.output.tag_config("alert", foreground="red")
        self.output.tag_config("status", foreground="#00d4ff")
        self.output.tag_config("capture", foreground="#aaaaaa")

        self.process = None
        self.alert_count = 0
        self.packet_count = 0

    # ---------- INTERFACE HANDLER ----------
    def get_interfaces(self):
        interfaces = get_if_list()
        nice = []

        for iface in interfaces:
            try:
                ip = get_if_addr(iface)
            except:
                ip = "No IP"

            if ip == "0.0.0.0" or "Loopback" in iface:
                continue

            label = f"{iface} ({ip})"
            nice.append(label)
            self.iface_map[label] = iface

        return nice

    # ---------- STATS ----------
    def create_stat(self, parent, text, col):
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.grid(row=0, column=col, padx=15)

        label_title = tk.Label(frame, text=text,
                               bg="#2a2a3c", fg="white",
                               font=("Arial", 10))
        label_title.pack()

        value = tk.Label(frame, text="0",
                         bg="#2a2a3c", fg="#00ffcc",
                         font=("Arial", 16, "bold"))
        value.pack()

        return value

    # ---------- START IDS ----------
    def start_ids(self):
        selected = self.iface_var.get()
        iface = self.iface_map.get(selected)

        if not iface:
            self.log("Select interface first\n", "alert")
            return

        cmd = [sys.executable, "ids.py", "--iface", iface]

        if platform.system() != "Windows":
            cmd.insert(0, "sudo")

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        self.status_label.config(text="Running")
        threading.Thread(target=self.read_output, daemon=True).start()

    # ---------- STOP IDS ----------
    def stop_ids(self):
        if self.process:
            self.process.terminate()
            self.status_label.config(text="Stopped")
            self.log("IDS Stopped\n", "status")

    # ---------- READ OUTPUT ----------
    def read_output(self):
        for line in self.process.stdout:
            self.packet_count += 1
            self.packet_label.config(text=str(self.packet_count))

            if "ALERT" in line:
                self.alert_count += 1
                self.alert_label.config(text=str(self.alert_count))
                self.log(line, "alert")

            elif "STATUS" in line:
                self.log(line, "status")

            else:
                self.log(line, "capture")

    # ---------- LOG ----------
    def log(self, text, tag=None):
        self.output.insert(tk.END, text, tag)
        self.output.see(tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()