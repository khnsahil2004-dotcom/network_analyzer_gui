import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
import socket
import time

class NetworkAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🎯 Smart Network Device Identifier")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Variables
        self.is_capturing = False
        self.capture_thread = None
        self.packet_count = 0
        self.protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.top_ips = {}
        self.your_ip = ""
        self.gateway_ip = ""
        self.local_network_prefix = ""
        
        self.setup_gui()
        self.identify_devices()
    
    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="🎯 Smart Network Device Identifier", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Device Info Frame
        info_frame = ttk.LabelFrame(main_frame, text="📱 Device Information", padding="10")
        info_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Your device info
        self.your_ip_var = tk.StringVar(value="Detecting...")
        self.phone_ip_var = tk.StringVar(value="Detecting...")
        
        ttk.Label(info_frame, text="💻 Your Laptop IP:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W)
        ttk.Label(info_frame, textvariable=self.your_ip_var, foreground="blue").grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(info_frame, text="📱 Phone/Hotspot IP:", font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky=tk.W)
        ttk.Label(info_frame, textvariable=self.phone_ip_var, foreground="green").grid(row=1, column=1, sticky=tk.W, padx=(10, 0))
        
        # Control Frame
        control_frame = ttk.LabelFrame(main_frame, text="⚙️ Controls", padding="10")
        control_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Duration selection
        ttk.Label(control_frame, text="Capture Duration (seconds):").grid(row=0, column=0, sticky=tk.W)
        self.duration_var = tk.StringVar(value="30")
        duration_spinbox = ttk.Spinbox(control_frame, from_=10, to=120, increment=5, 
                                      textvariable=self.duration_var, width=10)
        duration_spinbox.grid(row=0, column=1, padx=(10, 0))
        
        # Buttons
        self.start_button = ttk.Button(control_frame, text="▶️ Start Analysis", 
                                      command=self.start_analysis)
        self.start_button.grid(row=0, column=2, padx=(20, 10))
        
        self.stop_button = ttk.Button(control_frame, text="⏹️ Stop", 
                                     command=self.stop_analysis, state='disabled')
        self.stop_button.grid(row=0, column=3)
        
        # Progress bar
        self.progress = ttk.Progressbar(control_frame, mode='indeterminate')
        self.progress.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Results Notebook
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        
        # Summary Tab
        summary_frame = ttk.Frame(notebook)
        notebook.add(summary_frame, text="📊 Summary")
        
        self.summary_text = scrolledtext.ScrolledText(summary_frame, height=15, width=70)
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Devices Tab
        devices_frame = ttk.Frame(notebook)
        notebook.add(devices_frame, text="📱 Devices")
        
        self.devices_text = scrolledtext.ScrolledText(devices_frame, height=15, width=70)
        self.devices_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        summary_frame.columnconfigure(0, weight=1)
        summary_frame.rowconfigure(0, weight=1)
        devices_frame.columnconfigure(0, weight=1)
        devices_frame.rowconfigure(0, weight=1)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready to analyze network traffic...")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
    
    def identify_devices(self):
        """Identify your laptop and phone IPs"""
        try:
            # Get your laptop's IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.your_ip = s.getsockname()[0]
            s.close()
            
            # Set in GUI
            self.your_ip_var.set(self.your_ip)
            
            # Determine likely gateway IP
            ip_parts = self.your_ip.split('.')
            if len(ip_parts) == 4:
                self.local_network_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."
                self.gateway_ip = f"{self.local_network_prefix}1"  # Most common
                self.phone_ip_var.set(self.gateway_ip)
            else:
                self.phone_ip_var.set("Not detected")
                
        except Exception as e:
            self.your_ip_var.set("Error detecting")
            self.phone_ip_var.set("Error detecting")
    
    def packet_handler(self, packet):
        """Handle each captured packet"""
        if not self.is_capturing:
            return
            
        self.packet_count += 1
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Track IP addresses
            self.top_ips[src_ip] = self.top_ips.get(src_ip, 0) + 1
            self.top_ips[dst_ip] = self.top_ips.get(dst_ip, 0) + 1
            
            # Protocol counting
            if TCP in packet:
                self.protocol_stats["TCP"] += 1
            elif UDP in packet:
                self.protocol_stats["UDP"] += 1
            elif ICMP in packet:
                self.protocol_stats["ICMP"] += 1
            else:
                self.protocol_stats["Other"] += 1
        else:
            self.protocol_stats["Other"] += 1
    
    def capture_packets(self, duration):
        """Capture packets in a separate thread"""
        try:
            sniff(prn=self.packet_handler, timeout=duration, store=0)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Capture failed: {str(e)}"))
        
        # Update GUI when done
        self.root.after(0, self.analysis_completed)
    
    def start_analysis(self):
        """Start network analysis"""
        if self.is_capturing:
            return
            
        try:
            duration = int(self.duration_var.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid duration")
            return
        
        # Reset counters
        self.packet_count = 0
        self.protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.top_ips = {}
        
        # Update UI
        self.is_capturing = True
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.progress.start()
        self.status_var.set(f"Analyzing network traffic for {duration} seconds...")
        
        # Clear text areas
        self.summary_text.delete(1.0, tk.END)
        self.devices_text.delete(1.0, tk.END)
        
        # Start capture in background thread
        self.capture_thread = threading.Thread(target=self.capture_packets, args=(duration,))
        self.capture_thread.daemon = True
        self.capture_thread.start()
    
    def stop_analysis(self):
        """Stop network analysis"""
        self.is_capturing = False
        self.analysis_completed()
    
    def analysis_completed(self):
        """Called when analysis is completed"""
        self.is_capturing = False
        self.progress.stop()
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.status_var.set("Analysis completed!")
        
        # Display results
        self.display_results()
    
    def display_results(self):
        """Display analysis results in GUI"""
        # Summary tab
        summary = f"""🎯 NETWORK ANALYSIS SUMMARY
{'='*50}
Total Packets Analyzed: {self.packet_count}

🌐 PROTOCOL DISTRIBUTION:
{'-'*30}
"""
        
        total_packets = sum(self.protocol_stats.values())
        if total_packets == 0:
            total_packets = 1
            
        for protocol, count in self.protocol_stats.items():
            percentage = (count / total_packets) * 100
            summary += f"{protocol:8} : {count:5} packets ({percentage:5.1f}%)\n"
        
        your_packets = self.top_ips.get(self.your_ip, 0)
        phone_packets = self.top_ips.get(self.gateway_ip, 0)
        
        summary += f"""
📋 DEVICE TRAFFIC SUMMARY:
{'-'*25}
Your laptop ({self.your_ip}): {your_packets} packets
Phone/hotspot ({self.gateway_ip}): {phone_packets} packets
"""
        
        # Find other local devices
        local_devices = 0
        local_packets = 0
        for ip, count in self.top_ips.items():
            if (self.local_network_prefix and 
                ip.startswith(self.local_network_prefix) and 
                ip != self.your_ip and 
                ip != self.gateway_ip):
                local_devices += 1
                local_packets += count
        
        summary += f"Other local devices: {local_devices} devices, {local_packets} packets\n"
        
        self.summary_text.insert(tk.END, summary)
        
        # Devices tab
        if self.top_ips:
            devices = "📱 DETECTED DEVICES & TRAFFIC:\n"
            devices += "="*50 + "\n\n"
            
            sorted_ips = sorted(self.top_ips.items(), key=lambda x: x[1], reverse=True)
            
            for ip, count in sorted_ips[:25]:  # Show top 25 IPs
                # Identify device type
                if ip == self.your_ip:
                    device_type = "💻 YOUR LAPTOP"
                    color = "blue"
                elif ip == self.gateway_ip:
                    device_type = "📱 YOUR PHONE (Hotspot)"
                    color = "green"
                elif self.local_network_prefix and ip.startswith(self.local_network_prefix):
                    if ip.endswith('.1') or ip.endswith('.254'):
                        device_type = "📱 PHONE/HOTSPOT?"
                    else:
                        device_type = "📱 OTHER LOCAL DEVICE"
                    color = "orange"
                else:
                    device_type = "🌐 INTERNET"
                    color = "purple"
                
                devices += f"{ip:15} : {count:5} packets [{device_type}]\n"
            
            self.devices_text.insert(tk.END, devices)
        else:
            self.devices_text.insert(tk.END, "No network traffic detected.")
    
    def on_closing(self):
        """Handle window closing"""
        self.is_capturing = False
        self.root.destroy()

def main():
    root = tk.Tk()
    app = NetworkAnalyzerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()