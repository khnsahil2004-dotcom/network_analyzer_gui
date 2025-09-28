
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, PcapWriter, conf, get_if_list
import socket
import time
import os
from collections import defaultdict, deque
import statistics

# ---------- Configuration ----------
PCAP_DIR = "captures"                  # where to save sample pcaps
SAMPLE_SAVE_THRESHOLD = 50            # save pcap when packets from an IP exceed this count
SAMPLE_CAPTURE_COUNT = 200            # number of packets to save for suspicious IP
IGNORE_BROADCASTS = True              # ignore broadcast/multicast addresses
SYN_SUSPECT_THRESHOLD = 100           # many SYNs with low completions => suspicious
TTL_VARIANCE_THRESHOLD = 10           # excessive TTL variance considered suspicious
# -----------------------------------

class EnhancedNetworkAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🎯 Enhanced Smart Network Device Identifier")
        self.root.geometry("920x720")
        self.root.configure(bg='#f7f7f7')

        # Capture state
        self.is_capturing = False
        self.capture_thread = None

        # Metrics
        self.packet_count = 0
        self.protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.top_ips = defaultdict(int)
        self.ip_mac_map = {}            # ip -> mac
        self.mac_ip_map = defaultdict(set)  # mac -> set(ips)
        self.ip_ttl_history = defaultdict(lambda: deque(maxlen=100))
        self.ip_syn_counts = defaultdict(int)
        self.ip_synack_counts = defaultdict(int)
        self.ip_sample_written = set()

        # network info
        self.your_ip = ""
        self.gateway_ip = ""
        self.local_network_prefix = ""

        # scapy pcap writer pool
        os.makedirs(PCAP_DIR, exist_ok=True)
        self.pcap_writers = {}  # ip -> PcapWriter when sampling

        self.setup_gui()
        self.identify_devices()

    def setup_gui(self):
        main_frame = ttk.Frame(self.root, padding=12)
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        title = ttk.Label(main_frame, text="🎯 Enhanced Smart Network Device Identifier", font=('Arial', 18, 'bold'))
        title.grid(row=0, column=0, columnspan=4, pady=(0,12))

        # Interface selection
        ttk.Label(main_frame, text="Interface:", font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky=tk.W)
        self.iface_var = tk.StringVar()
        iface_list = get_if_list()
        self.iface_combo = ttk.Combobox(main_frame, values=iface_list, textvariable=self.iface_var, state="readonly", width=40)
        self.iface_combo.grid(row=1, column=1, columnspan=2, sticky=(tk.W), padx=(6,0))
        # Default: choose Scapy default iface or first available
        default_iface = conf.iface if conf.iface else (iface_list[0] if iface_list else "")
        self.iface_var.set(default_iface)

        # Device info labels
        self.your_ip_var = tk.StringVar(value="Detecting...")
        self.gateway_ip_var = tk.StringVar(value="Detecting...")
        ttk.Label(main_frame, text="Your IP:").grid(row=2, column=0, sticky=tk.W, pady=6)
        ttk.Label(main_frame, textvariable=self.your_ip_var, foreground="blue").grid(row=2, column=1, sticky=tk.W)
        ttk.Label(main_frame, text="Gateway/IP (hotspot):").grid(row=2, column=2, sticky=tk.W)
        ttk.Label(main_frame, textvariable=self.gateway_ip_var, foreground="green").grid(row=2, column=3, sticky=tk.W)

        # Duration
        ttk.Label(main_frame, text="Duration (s):").grid(row=3, column=0, sticky=tk.W, pady=6)
        self.duration_var = tk.StringVar(value="30")
        duration_spinbox = ttk.Spinbox(main_frame, from_=10, to=600, increment=10, textvariable=self.duration_var, width=12)
        duration_spinbox.grid(row=3, column=1, sticky=tk.W)

        # Capture controls
        self.start_btn = ttk.Button(main_frame, text="▶️ Start Analysis", command=self.start_analysis)
        self.start_btn.grid(row=3, column=2, padx=6)
        self.stop_btn = ttk.Button(main_frame, text="⏹️ Stop", command=self.stop_analysis, state=tk.DISABLED)
        self.stop_btn.grid(row=3, column=3, padx=6)

        # Options row
        self.save_samples_var = tk.IntVar(value=1)
        ttk.Checkbutton(main_frame, text="Save suspicious samples (PCAP)", variable=self.save_samples_var).grid(row=4, column=0, sticky=tk.W)
        self.ignore_broadcasts_var = tk.IntVar(value=1 if IGNORE_BROADCASTS else 0)
        ttk.Checkbutton(main_frame, text="Ignore broadcast/multicast", variable=self.ignore_broadcasts_var).grid(row=4, column=1, sticky=tk.W)
        ttk.Button(main_frame, text="Clear Results", command=self.clear_results).grid(row=4, column=3, sticky=tk.E)

        # Progress and status
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=5, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(6,8))
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN).grid(row=6, column=0, columnspan=4, sticky=(tk.W, tk.E))

        # Notebook for results
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=7, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(8,0))

        # Summary Tab
        summary_frame = ttk.Frame(notebook)
        notebook.add(summary_frame, text="📊 Summary")
        self.summary_text = scrolledtext.ScrolledText(summary_frame, height=18)
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Devices Tab
        devices_frame = ttk.Frame(notebook)
        notebook.add(devices_frame, text="📱 Devices")
        self.devices_text = scrolledtext.ScrolledText(devices_frame, height=18)
        self.devices_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Suspicious Tab
        suspicious_frame = ttk.Frame(notebook)
        notebook.add(suspicious_frame, text="⚠️ Suspicious")
        self.suspicious_text = scrolledtext.ScrolledText(suspicious_frame, height=10)
        self.suspicious_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Grid expand
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(7, weight=1)

    def identify_devices(self):
        """Identify local IP and guess gateway/hotspot."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.your_ip = s.getsockname()[0]
            s.close()
            self.your_ip_var.set(self.your_ip)

            parts = self.your_ip.split('.')
            if len(parts) == 4:
                self.local_network_prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."
                self.gateway_ip = f"{self.local_network_prefix}1"
                self.gateway_ip_var.set(self.gateway_ip)
            else:
                self.gateway_ip_var.set("Unknown")
        except Exception as e:
            self.your_ip_var.set("Error")
            self.gateway_ip_var.set("Error")

    def should_ignore_packet(self, pkt):
        """Decide whether to ignore broadcast/multicast or non-IP traffic."""
        if not pkt.haslayer(IP):
            return True  # ignore non-IP packets for device counting
        src = pkt[IP].src
        dst = pkt[IP].dst
        if self.ignore_broadcasts_var.get():
            if dst == "255.255.255.255":
                return True
            if dst.startswith("224.") or src.startswith("224."):
                return True
        return False

    def packet_handler(self, packet):
        """Process each captured packet (called in sniff thread)."""
        if not self.is_capturing:
            return

        self.packet_count += 1

        # Only consider IP packets for device counters
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Track IP packet counts
            self.top_ips[src_ip] += 1
            self.top_ips[dst_ip] += 1

            # Track MAC mapping if Ether layer present
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                # record mapping src_ip -> src_mac
                if src_ip not in self.ip_mac_map:
                    self.ip_mac_map[src_ip] = src_mac
                else:
                    # conflict detection
                    if self.ip_mac_map[src_ip] != src_mac:
                        # flag conflict
                        self.root.after(0, lambda ip=src_ip, old=self.ip_mac_map[src_ip], new=src_mac: 
                                        self.flag_suspicious(f"IP->MAC conflict for {ip}: {old} vs {new}"))
                # populate reverse mapping
                self.mac_ip_map[src_mac].add(src_ip)

            # Protocol counts
            if TCP in packet:
                self.protocol_stats["TCP"] += 1
                # analyze TCP flags for SYN / SYN-ACK
                tcp = packet[TCP]
                flags = tcp.flags
                if flags & 0x02:  # SYN
                    self.ip_syn_counts[src_ip] += 1
                if flags & 0x12:  # SYN-ACK
                    self.ip_synack_counts[src_ip] += 1
            elif UDP in packet:
                self.protocol_stats["UDP"] += 1
            elif ICMP in packet:
                self.protocol_stats["ICMP"] += 1
            else:
                self.protocol_stats["Other"] += 1

            # TTL logging
            ttl = packet[IP].ttl
            self.ip_ttl_history[src_ip].append(ttl)

            # suspicious heuristics
            # 1) excessive SYNs without corresponding SYN-ACKs
            syns = self.ip_syn_counts.get(src_ip, 0)
            synacks = self.ip_synack_counts.get(src_ip, 0)
            if syns > SYN_SUSPECT_THRESHOLD and synacks < (syns * 0.1):
                self.root.after(0, lambda ip=src_ip: self.flag_suspicious(f"SYN-heavy activity from {ip} (possible scan/flood)"))

            # 2) TTL variance detection
            ttls = list(self.ip_ttl_history[src_ip])
            if len(ttls) >= 6:
                try:
                    var = statistics.pstdev(ttls)
                    if var > TTL_VARIANCE_THRESHOLD:
                        self.root.after(0, lambda ip=src_ip, v=var: self.flag_suspicious(f"High TTL variance for {ip}: {v:.2f} (possible spoofing/MITM)"))
                except Exception:
                    pass

            # 3) save sample PCAP for heavy IPs (if enabled)
            if self.save_samples_var.get() and (self.top_ips[src_ip] > SAMPLE_SAVE_THRESHOLD) and (src_ip not in self.ip_sample_written):
                # start writer and mark
                path = os.path.join(PCAP_DIR, f"{src_ip.replace('.', '_')}_sample.pcap")
                try:
                    writer = PcapWriter(path, append=True, sync=True)
                    self.pcap_writers[src_ip] = {'writer': writer, 'count': 0}
                    self.ip_sample_written.add(src_ip)
                    self.root.after(0, lambda ip=src_ip: self.status_var.set(f"Started saving PCAP sample for {ip} -> {path}"))
                except Exception as e:
                    self.root.after(0, lambda e=e: self.status_var.set(f"PCAP writer start failed: {e}"))

            # if writer exists, write packet until SAMPLE_CAPTURE_COUNT
            if src_ip in self.pcap_writers:
                writer_info = self.pcap_writers[src_ip]
                writer_info['writer'].write(packet)
                writer_info['count'] += 1
                if writer_info['count'] >= SAMPLE_CAPTURE_COUNT:
                    try:
                        writer_info['writer'].close()
                    except Exception:
                        pass
                    del self.pcap_writers[src_ip]
                    self.root.after(0, lambda ip=src_ip: self.status_var.set(f"Saved sample pcap for {ip}"))

        else:
            # non-IP packets
            self.protocol_stats["Other"] += 1

    def capture_packets(self, duration, iface):
        try:
            # sniff on chosen interface; store=0 ensures low memory
            sniff(iface=iface, prn=self.packet_handler, timeout=duration, store=0, promisc=True)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Capture failed: {str(e)}"))
        finally:
            self.root.after(0, self.analysis_completed)

    def start_analysis(self):
        if self.is_capturing:
            return

        # check privileges hint
        if os.name != 'nt' and os.geteuid() != 0:
            # warn - capture usually requires root on Unix
            if not messagebox.askyesno("Privileges required", "Packet capture usually requires root privileges. Continue anyway?"):
                return

        try:
            duration = int(self.duration_var.get())
        except ValueError:
            messagebox.showerror("Invalid", "Enter a valid duration.")
            return

        iface = self.iface_var.get()
        if not iface:
            messagebox.showerror("Interface", "Select capture interface.")
            return

        # reset stats
        self.packet_count = 0
        self.protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.top_ips.clear()
        self.ip_mac_map.clear()
        self.mac_ip_map.clear()
        self.ip_ttl_history.clear()
        self.ip_syn_counts.clear()
        self.ip_synack_counts.clear()
        self.ip_sample_written.clear()

        self.is_capturing = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.progress.start()
        self.status_var.set(f"Capturing on {iface} for {duration}s...")

        self.summary_text.delete(1.0, tk.END)
        self.devices_text.delete(1.0, tk.END)
        self.suspicious_text.delete(1.0, tk.END)

        # start thread
        self.capture_thread = threading.Thread(target=self.capture_packets, args=(duration, iface), daemon=True)
        self.capture_thread.start()

    def stop_analysis(self):
        # Setting flag stops handler logic but sniff() will finish after timeout; this is soft stop
        self.is_capturing = False
        self.status_var.set("Stopping capture... (may take a few seconds)")

    def analysis_completed(self):
        self.is_capturing = False
        self.progress.stop()
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_var.set("Analysis completed.")
        self.display_results()

    def display_results(self):
        total_packets = sum(self.protocol_stats.values())
        if total_packets == 0:
            total_packets = 1

        summary = f"🎯 NETWORK ANALYSIS SUMMARY\n{'='*70}\n"
        summary += f"Total packets observed (counted): {self.packet_count}\n\n"
        summary += "PROTOCOL DISTRIBUTION:\n"
        for proto, count in self.protocol_stats.items():
            summary += f"  {proto:6} : {count:6} packets ({(count/total_packets)*100:5.1f}%)\n"

        # device summary
        your_count = self.top_ips.get(self.your_ip, 0)
        gateway_count = self.top_ips.get(self.gateway_ip, 0)
        summary += f"\nDEVICE TRAFFIC SUMMARY:\n  Your laptop ({self.your_ip}): {your_count} packets\n  Gateway/Hotspot ({self.gateway_ip}): {gateway_count} packets\n"

        # local devices count
        local_devices = []
        local_packets = 0
        for ip, cnt in self.top_ips.items():
            if self.local_network_prefix and ip.startswith(self.local_network_prefix) and ip not in (self.your_ip, self.gateway_ip):
                local_devices.append((ip, cnt))
                local_packets += cnt

        summary += f"Other local devices: {len(local_devices)} devices, {local_packets} packets\n"
        self.summary_text.insert(tk.END, summary)

        # Devices tab detailed listing
        devices = "📱 DETECTED DEVICES & TRAFFIC\n" + "="*70 + "\n\n"
        sorted_ips = sorted(self.top_ips.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_ips[:200]:
            # classify
            if ip == self.your_ip:
                dtype = "💻 YOUR LAPTOP"
            elif ip == self.gateway_ip:
                dtype = "📱 GATEWAY/HOTSPOT"
            elif self.local_network_prefix and ip.startswith(self.local_network_prefix):
                dtype = "📱 LOCAL DEVICE"
            else:
                dtype = "🌐 EXTERNAL/INTERNET"
            mac = self.ip_mac_map.get(ip, "N/A")
            ttls = list(self.ip_ttl_history.get(ip, []))
            ttl_info = f"TTL samples: {len(ttls)}"
            devices += f"{ip:16} | {count:6} pkts | {dtype:18} | MAC:{mac:17} | {ttl_info}\n"

        self.devices_text.insert(tk.END, devices)

        # Suspicious tab: list gathered flags and heuristics
        suspicious = "⚠️ SUSPICIOUS FINDINGS (heuristic-based)\n" + "="*70 + "\n\n"
        # IP->MAC conflicts
        for ip, mac in self.ip_mac_map.items():
            # check reverse mapping count
            if len(self.mac_ip_map.get(mac, {})) > 1:
                suspicious += f"IP->MAC anomaly: {ip} maps to {mac} but that MAC also used by multiple IPs {self.mac_ip_map[mac]}\n"

        # SYN heavy
        for ip, syn_count in self.ip_syn_counts.items():
            synacks = self.ip_synack_counts.get(ip, 0)
            if syn_count > SYN_SUSPECT_THRESHOLD and synacks < (syn_count * 0.1):
                suspicious += f"SYN-heavy: {ip} sent {syn_count} SYNs, only {synacks} SYN-ACKs -> possible scan/flood\n"

        # TTL variance
        for ip, ttls in self.ip_ttl_history.items():
            if len(ttls) >= 6:
                try:
                    var = statistics.pstdev(list(ttls))
                    if var > TTL_VARIANCE_THRESHOLD:
                        suspicious += f"High TTL variance: {ip} (var={var:.2f}) -> possible spoof/MITM\n"
                except Exception:
                    pass

        if suspicious.strip() == "⚠️ SUSPICIOUS FINDINGS (heuristic-based)":
            suspicious += "No obvious suspicious behavior detected by heuristics.\n"

        self.suspicious_text.insert(tk.END, suspicious)

    def flag_suspicious(self, message):
        """Add a message to suspicious tab and show a short status."""
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.suspicious_text.insert(tk.END, f"[{ts}] {message}\n")
        self.status_var.set(f"Suspicious: {message}")

    def clear_results(self):
        self.summary_text.delete(1.0, tk.END)
        self.devices_text.delete(1.0, tk.END)
        self.suspicious_text.delete(1.0, tk.END)
        self.status_var.set("Cleared results.")

    def on_closing(self):
        self.is_capturing = False
        # close any open pcap writers
        for winfo in list(self.pcap_writers.values()):
            try:
                winfo['writer'].close()
            except Exception:
                pass
        self.root.destroy()

def main():
    root = tk.Tk()
    app = EnhancedNetworkAnalyzerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
