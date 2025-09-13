import threading
import scapy.all as scapy
import tkinter as tk
from tkinter import ttk, messagebox

captured_packets = []
stop_sniffing_flag = False

def get_interfaces():
    try:
        return scapy.get_if_list()
    except Exception as e:
        messagebox.showerror("Error", f"Could not retrieve interfaces: {e}")
        return []

def process_packet(packet):
    if stop_sniffing_flag:
        return
    try:
        src = packet[0][1].src if hasattr(packet[0][1], 'src') else "Unknown"
        dst = packet[0][1].dst if hasattr(packet[0][1], 'dst') else "Unknown"
        proto = packet[0][1].name if hasattr(packet[0][1], 'name') else packet.summary()
        packet_list.insert('', 'end', values=(src, dst, proto))
    except Exception:
        pass

def sniff_packets(iface):
    scapy.sniff(iface=iface, prn=process_packet, store=False, stop_filter=lambda x: stop_sniffing_flag)

def start_sniffing():
    global stop_sniffing_flag
    iface = iface_var.get()
    if not iface:
        messagebox.showerror("Error", "Please select an interface.")
        return
    stop_sniffing_flag = False
    start_btn.config(state='disabled')
    stop_btn.config(state='normal')
    threading.Thread(target=sniff_packets, args=(iface,), daemon=True).start()

def stop_sniffing():
    global stop_sniffing_flag
    stop_sniffing_flag = True
    start_btn.config(state='normal')
    stop_btn.config(state='disabled')
    messagebox.showinfo("Stopped", "Sniffing has been stopped.")

root = tk.Tk()
root.title("CodeAlpha Network Sniffer")
root.geometry("750x450")

tk.Label(root, text="Choose Interface").pack(pady=5)
iface_var = tk.StringVar()
interfaces = get_interfaces()
iface_dropdown = ttk.Combobox(root, textvariable=iface_var, values=interfaces, width=70)
iface_dropdown.pack(pady=5)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)
start_btn = tk.Button(btn_frame, text="Start Sniffing", command=start_sniffing)
start_btn.pack(side='left', padx=5)
stop_btn = tk.Button(btn_frame, text="Stop Sniffing", command=stop_sniffing, state='disabled')
stop_btn.pack(side='left', padx=5)

columns = ('Source', 'Destination', 'Protocol')
packet_list = ttk.Treeview(root, columns=columns, show='headings', height=15)
for col in columns:
    packet_list.heading(col, text=col)
    packet_list.column(col, width=220)
packet_list.pack(fill='both', expand=True)

root.mainloop()
