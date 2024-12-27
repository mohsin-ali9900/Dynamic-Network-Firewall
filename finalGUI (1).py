import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import pydivert
import threading
from tkinter import messagebox, filedialog
import socket
import os
import psutil
# import matplotlib.pyplot as plt
# from matplotlib.animation import FuncAnimation
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import csv

rules = []
packet_log_data = []
capture_running = False

# Data for the live chart
time_data = []
blocked_data = []
allowed_data = []

# Add these global variables to track packet counts
total_packets = 0
blocked_packets = 0
allowed_packets = 0


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except:
        local_ip = '127.0.0.1' 
    finally:
        s.close()
    return local_ip

def capture_packets():
    global capture_running
    try:
        local_ip = get_local_ip()
        with pydivert.WinDivert("true") as w:
            for packet in w:
                if not capture_running: 
                    break
                src_ip = packet.src_addr
                dst_ip = packet.dst_addr
                src_port = packet.src_port
                dst_port = packet.dst_port
                protocol = "TCP" if packet.tcp else "UDP" if packet.udp else "Other"
                # direction = "Inbound" if packet.is_inbound else "Outbound"
                status = "Allowed"

                if dst_ip == local_ip:
                    direction = "Inbound"
                else:
                    direction = "Outbound"
                for rule in rules:
                    if rule["type"] == "port" and dst_port == int(rule["value"]) and rule["protocol"] == protocol and rule["direction"] in [direction, "Both"]:
                        status = rule["action"]
                        break
                    elif rule["type"] == "ip address" and dst_ip == rule["value"]:
                        status = rule["action"]
                        break
                    elif rule["type"] == "program":
                        if match_program(packet, rule["value"]):  # Match program path
                            status = rule["action"]
                            break

                add_to_packet_log(src_ip, dst_ip, src_port, dst_port, protocol, direction, status)

                if status == "Blocked":
                    continue
                w.send(packet)
    except Exception as e:
        print(f"Error in packet capture: {e}")

def match_program(packet, program_path):
    try:
        for proc in psutil.process_iter(['pid', 'exe']):
            if proc.info['exe'] == program_path:
                connections = proc.connections(kind='inet')
                for conn in connections:
                    if conn.laddr.port == packet.src_port or conn.raddr.port == packet.dst_port:
                        return True
    except Exception as e:
        print(f"Error matching program: {e}")
    return False

def update_packet_counters(status):
    global total_packets, blocked_packets, allowed_packets
    total_packets += 1
    if status == "Blocked":
        blocked_packets += 1
    else:
        allowed_packets += 1
        
    total_label.config(text=f"Total Packets: {total_packets}")
    blocked_label.config(text=f"Blocked Packets: {blocked_packets}")
    allowed_label.config(text=f"Allowed Packets: {allowed_packets}")


def add_to_packet_log(src_ip, dst_ip, src_port, dst_port, protocol, direction, status):
    global packet_log_data
    packet_entry = (src_ip, dst_ip, src_port, dst_port, protocol, direction, status)
    packet_log_data.append(packet_entry)
    packet_log_tree.insert("", ttk.END, values=packet_entry)
    update_packet_counters(status)

def start_capture():
    global capture_running
    if capture_running:
        messagebox.showinfo("Capture Running", "Packet capture is already running.")
        return
    capture_running = True
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    messagebox.showinfo("Capture Started", "Packet capture and filtering started.")
    
def stop_capture():
    global capture_running
    if not capture_running:
        messagebox.showinfo("Capture Stopped", "Packet capture is not running.")
        return
    capture_running = False
    messagebox.showinfo("Capture Stopped", "Packet capture and filtering stopped.")

def add_rule():
    rule_type = rule_type_var.get()
    value = rule_value_entry.get()
    protocol = protocol_menu.get()
    action = action_var.get()
    direction = direction_var.get()
    if rule_type and value and action:
        if rule_type == "port":
            rules.append({"type": rule_type, "value": value, "protocol": protocol, "action": action, "direction":direction})
        elif rule_type == "ip address":
            rules.append({"type": rule_type, "value": value, "action": action, "direction":direction})
        elif rule_type == "program":
            if os.path.isfile(value):
                rules.append({"type":rule_type, "value":value, "action":action, "direction":direction})
            else:
                messagebox.showwarning("Error","Invalid Program Path")
                return
        update_rule_list()
        print(rules)
        messagebox.showinfo("Success", f"Rule added: {rule_type} = {value}, Protocol = {protocol}, Action = {action}")
    else:
        messagebox.showwarning("Error", "Please fill in all fields")

def update_rule_list():
    for item in rule_tree.get_children():
        rule_tree.delete(item)
    for rule in rules:
        if rule["type"] == "port":
            rule_tree.insert("", ttk.END, values=(rule["type"], rule["value"], rule["protocol"], rule["action"], rule["direction"]))
        else:
            rule_tree.insert("", ttk.END, values=(rule["type"], rule["value"], "N/A", rule["action"], rule["direction"]))

def delete_rule():
    selected_item = rule_tree.selection()
    if selected_item:
        rule_index = rule_tree.index(selected_item[0])
        del rules[rule_index]
        update_rule_list()
        messagebox.showinfo("Rule Deleted", "Selected rule has been deleted.")
    else:
        messagebox.showwarning("Error", "Please select a rule to delete")

def save_packet_logs_to_csv():
    try:
        file_path = "packet_logs.csv"  # You can ask the user to choose the path if necessary
        with open(file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Direction", "Status"])  # CSV header
            for packet in packet_log_data:
                writer.writerow(packet)
        messagebox.showinfo("Logs Saved", f"Packet logs have been saved to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while saving the logs: {e}")

def stop_capture_and_save_logs():
    global capture_running
    if not capture_running:
        messagebox.showinfo("Capture Stopped", "Packet capture is not running.")
        return
    
    # Stop packet capture
    capture_running = False
    # messagebox.showinfo("Capture Stopped", "Packet capture and filtering stopped.")
    
    # Save the logs to a CSV file
    save_packet_logs_to_csv()
    
    # Restart packet capture
    start_capture()


def filter_packet_log():
    criteria = filter_criteria_var.get()
    value = filter_value_entry.get()
    for item in packet_log_tree.get_children():
        packet_log_tree.delete(item)

    if not criteria or not value:
        messagebox.showwarning("Error", "Please select a filter criteria and enter a value")
        return

    for packet in packet_log_data:
        if criteria == "Destination IP" and packet[1] == value:
            packet_log_tree.insert("", ttk.END, values=packet)
        elif criteria == "Protocol" and packet[4] == value:
            packet_log_tree.insert("", ttk.END, values=packet)
        elif criteria == "Source IP" and packet[0] == value:
            packet_log_tree.insert("", ttk.END, values=packet)
        elif criteria == "Source Port" and str(packet[2]) == value:
            packet_log_tree.insert("", ttk.END, values=packet)
        elif criteria == "Destination Port" and str(packet[3]) == value:
            packet_log_tree.insert("", ttk.END, values=packet)
        elif criteria == "Status" and packet[6] == value:
            packet_log_tree.insert("", ttk.END, values=packet)
        elif criteria == "Direction" and str(packet[5]) == value:
            packet_log_tree.insert("", ttk.END, values=packet)       

        
def refresh_packet_log():
    filter_criteria_var.set("")
    filter_value_entry.delete(0, ttk.END)
    global total_packets, blocked_packets, allowed_packets
    total_packets = 0
    blocked_packets = 0
    allowed_packets = 0    
    
    for row in packet_log_tree.get_children():
        packet_log_tree.delete(row)
    packet_log_data.clear()
    start_capture()
    
def browse_program():
    file_path = filedialog.askopenfilename(title="Select Program", filetypes=[("Executable Files", "*.exe"), ("All Files", "*.*")])
    if file_path:
        rule_value_entry.delete(0, ttk.END)
        rule_value_entry.insert(0, file_path)        

def update_chart():
    time_data.append(len(time_data))  # Increment time
    blocked_data.append(blocked_packets)
    allowed_data.append(allowed_packets)
    ax.clear()
    ax.plot(time_data, blocked_data, label="Blocked Packets", color="red")
    ax.plot(time_data, allowed_data, label="Allowed Packets", color="green")
    ax.set_title("Packet Traffic Over Time")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Packet Count")
    ax.legend()
    canvas.draw()
    visualization_tab.after(1000, update_chart)

def show_chart():
    global ax, canvas
    fig = Figure(figsize=(5, 4), dpi=100)
    ax = fig.add_subplot(111)
    ax.set_title("Packet Traffic Over Time")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Packet Count")
    canvas = FigureCanvasTkAgg(fig, master=visualization_frame)
    canvas_widget = canvas.get_tk_widget()
    canvas_widget.grid(row=2, column=1, columnspan=5, padx=10, pady=10, sticky="nsew")

def toggle_theme():
    current_theme = app.style.theme_use()
    if current_theme == "cosmo":
        app.style.theme_use("darkly")
    else:
        app.style.theme_use("cosmo") 
        
def update_rule_ui(*args):
    rule_type = rule_type_var.get()
    if rule_type == "port":
        rule_value_label.config(text="Value:")
        protocol_label.grid(row=0, column=4)
        protocol_menu.grid(row=0, column=5)
        browse_button.grid_remove()
    elif rule_type == "ip address":
        rule_value_label.config(text="IP Address:")
        protocol_label.grid_remove()
        protocol_menu.grid_remove()
        browse_button.grid_remove()
    elif rule_type == "program":
        rule_value_label.config(text="Program Path:")
        protocol_label.grid_remove()
        protocol_menu.grid_remove()
        browse_button.grid(row=0,column=4)

app = ttk.Window(themename="cosmo")
app.title("Enhanced Dynamic Network Firewall")
app.geometry("1200x800")

notebook = ttk.Notebook(app)
rules_tab = ttk.Frame(notebook)
logs_tab = ttk.Frame(notebook)
visualization_tab = ttk.Frame(notebook)
settings_tab = ttk.Frame(notebook)

notebook.add(rules_tab, text="Rules")
notebook.add(logs_tab, text="Packet Logs")
notebook.add(visualization_tab,text="Visualization")
notebook.add(settings_tab, text="Settings")
notebook.pack(expand=True, fill=BOTH, padx=10, pady=10)

style = ttk.Style()

style.configure("TNotebook", background="#ffffff", padding=5)
style.configure(
    "TNotebook.Tab",
    padding=[8, 4],
    font=("Helvetica", 10),
    background="#f0f0f0",
    foreground="black",
    relief="flat"
)

style.map(
    "TNotebook.Tab",
    background=[("selected", "#4CAF50")],
    foreground=[("selected", "white")]
)

style.configure("TNotebook", tabposition="nw")

# ------------- Rules Tab -------------
rules_frame = ttk.Labelframe(rules_tab, text="Add a Rule", padding=10)
rules_frame.pack(fill=X, padx=10, pady=10)

rule_type_label = ttk.Label(rules_frame, text="Rule Type:")
rule_type_label.grid(row=0, column=0, padx=5, pady=5)

rule_type_var = ttk.StringVar(value="port")
rule_type_menu = ttk.Combobox(rules_frame, textvariable=rule_type_var, values=["port", "ip address", "program"], state="readonly")
rule_type_menu.grid(row=0, column=1, padx=5, pady=5)
rule_type_var.trace("w", update_rule_ui)

rule_value_label = ttk.Label(rules_frame, text="Value:")
rule_value_label.grid(row=0, column=2, padx=5, pady=5)
rule_value_entry = ttk.Entry(rules_frame, width=30)
rule_value_entry.grid(row=0, column=3, padx=5, pady=5)

browse_button = ttk.Button(rules_frame, text="Browse", bootstyle=INFO, command=browse_program)
browse_button.grid(row=0, column=4, padx=5, pady=5)
browse_button.grid_remove()

protocol_label = ttk.Label(rules_frame, text="Protocol:")
protocol_label.grid(row=0, column=5, padx=5, pady=5)
protocol_menu = ttk.Combobox(rules_frame, values=["TCP", "UDP"], state="readonly")
protocol_menu.grid(row=0, column=6, padx=5, pady=5)

action_var = ttk.StringVar(value="Allowed")
action_label = ttk.Label(rules_frame, text="Action:")
action_label.grid(row=0, column=7, padx=5, pady=5)
action_menu = ttk.Combobox(rules_frame, textvariable=action_var, values=["Allowed", "Blocked"], state="readonly")
action_menu.grid(row=0, column=8, padx=5, pady=5)

direction_label = ttk.Label(rules_frame, text="Direction:")
direction_label.grid(row=0, column=9, padx=5, pady=5)
direction_var = ttk.StringVar(value="Both")
direction_menu = ttk.Combobox(rules_frame, textvariable=direction_var, values=["Inbound", "Outbound", "Both"], state="readonly")
direction_menu.grid(row=0, column=10, padx=5, pady=5)

add_rule_button = ttk.Button(rules_tab, text="Add Rule", bootstyle=SUCCESS, command=add_rule)
add_rule_button.pack(pady=5)

columns = ("Type", "Value", "Protocol", "Action", "Direction")

rule_tree = ttk.Treeview(rules_tab, columns=columns, show="headings", bootstyle="success")
rule_tree.heading("Type", text="Rule Type")
rule_tree.heading("Value", text="Rule Value")
rule_tree.heading("Protocol", text="Protocol")
rule_tree.heading("Action", text="Action")
rule_tree.heading("Direction", text="Direction")
# Set column alignment to center
for col in columns:
        rule_tree.heading(col, text=col)
        rule_tree.column(col, width=150, anchor="center")
rule_tree.pack(padx=10, pady=10, fill=BOTH, expand=True)

# Add a scrollbar to the rule tree
scrollbar = ttk.Scrollbar(rules_tab, orient="vertical", command=rule_tree.yview)
rule_tree.configure(yscroll=scrollbar.set)
scrollbar.pack(side=RIGHT, fill=Y)

delete_rule_button = ttk.Button(rules_tab, text="Delete Selected Rule", bootstyle=DANGER, command=delete_rule)
delete_rule_button.pack(pady=5)

# ------------- Logs Tab -------------
ttk.Label(logs_tab, text="Filter Packet Log").pack(pady=5)
filter_frame = ttk.Frame(logs_tab)
filter_frame.pack(pady=5)

filter_criteria_var = ttk.StringVar()
filter_criteria_label = ttk.Label(filter_frame, text="Filter By:")
filter_criteria_label.grid(row=0, column=0, padx=5, pady=5)

filter_criteria_menu = ttk.Combobox(
    filter_frame, 
    textvariable=filter_criteria_var, 
    values=["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Direction", "Status"],
    state="readonly"
)
filter_criteria_menu.grid(row=0, column=1, padx=5, pady=5)

filter_value_entry = ttk.Entry(filter_frame)
filter_value_entry.grid(row=0, column=2, padx=5, pady=5)

filter_button = ttk.Button(filter_frame, text="Filter Log", command=filter_packet_log)
filter_button.grid(row=0, column=3, padx=5, pady=5)

refresh_button = ttk.Button(filter_frame, text="Refresh", command=refresh_packet_log)
refresh_button.grid(row=0, column=4, padx=5, pady=5)

start_capture_button = ttk.Button(filter_frame, text="Start Capture", command=start_capture)
start_capture_button.grid(row=1, column=1, padx=5, pady=5)

stop_capture_button = ttk.Button(filter_frame, text="Stop Capture", command=stop_capture)
stop_capture_button.grid(row=1, column=2, padx=5, pady=5)

logs_label = ttk.Label(logs_tab, text="Packet Logs")
logs_label.pack(pady=5)

columns1 = ("Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Direction", "Status")
packet_log_tree = ttk.Treeview(logs_tab, columns=columns1, show="headings", bootstyle="success")
packet_log_tree.heading("Source IP", text="Source IP")
packet_log_tree.heading("Destination IP", text="Destination IP")
packet_log_tree.heading("Source Port", text="Source Port")
packet_log_tree.heading("Destination Port", text="Destination Port")
packet_log_tree.heading("Protocol", text="Protocol")
packet_log_tree.heading("Direction", text="Direction")
packet_log_tree.heading("Status", text="Status")
for col in columns1:
    packet_log_tree.heading(col, text=col)
    packet_log_tree.column(col, width=150, anchor="center")
packet_log_tree.pack(padx=10, pady=10, fill=BOTH, expand=True)

# Add a scrollbar to the packet log tree
packet_scrollbar = ttk.Scrollbar(logs_tab, orient="vertical", command=packet_log_tree.yview)
packet_log_tree.configure(yscroll=packet_scrollbar.set)
packet_scrollbar.pack(side=RIGHT, fill=Y)

save_logs_button = ttk.Button(logs_tab, text="Save Logs", command=stop_capture_and_save_logs)
save_logs_button.pack(padx=10, pady=10)


# ----------------- Visualization Tab -----------------
visualization_label = ttk.Label(visualization_tab,text="Visualization", font=("Helvetica", 16))
visualization_label.pack(pady=10)

visualization_frame = ttk.Labelframe(visualization_tab, text="Packet Visualization", padding=10)
visualization_frame.place(relx=0.5, rely=0.5, anchor="center")
show_chart()

# Add these labels to display packet counters
total_label = ttk.Label(visualization_frame, text="Total Packets: 0", font=("Helvetica", 12))
blocked_label = ttk.Label(visualization_frame, text="Blocked Packets: 0", font=("Helvetica", 12))
allowed_label = ttk.Label(visualization_frame, text="Allowed Packets: 0", font=("Helvetica", 12))

total_label.grid(row=0, column=1, padx=10, pady=5)
blocked_label.grid(row=0, column=2, padx=10, pady=5)
allowed_label.grid(row=0, column=3, padx=10, pady=5)

update_chart()

# ------------- Settings Tab -------------
settings_label = ttk.Label(settings_tab, text="Settings will go here.", font=("Arial", 12))
settings_label.pack(pady=10)

settings_frame = ttk.Labelframe(settings_tab, text="Settings", padding=10)
settings_frame.pack(fill=X, padx=10, pady=10)

# Add a button to toggle theme
toggle_button = ttk.Button(settings_frame, text="Toggle Light/Dark Mode", command=toggle_theme)
toggle_button.pack(pady=10)

# Add status bar
status_bar = ttk.Label(app, text="Ready", bootstyle=INVERSE)
status_bar.pack(side=BOTTOM, fill=X)

app.mainloop()
