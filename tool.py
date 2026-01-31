import socket
import subprocess
import ipaddress
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed
import ctypes
import sys
import os

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

def get_wifi_details(show_device_details=False):
    try:
        # Run ipconfig to get network details
        result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
        output = result.stdout

        # Find WiFi adapter (assuming it's named "Wireless LAN adapter Wi-Fi" or similar)
        lines = output.split('\n')
        wifi_ip = None
        wifi_subnet = None
        in_wifi_section = False

        for line in lines:
            line = line.strip()
            if 'Wireless LAN adapter' in line or 'Wi-Fi' in line:
                in_wifi_section = True
            elif 'adapter' in line and 'Wi-Fi' not in line:
                in_wifi_section = False
            elif in_wifi_section:
                if 'IPv4 Address' in line or 'IP Address' in line:
                    wifi_ip = line.split(':')[-1].strip()
                elif 'Subnet Mask' in line:
                    wifi_subnet = line.split(':')[-1].strip()

        if not wifi_ip or not wifi_subnet:
            return "Could not find WiFi IP or subnet. Ensure you are connected to WiFi."

        # Calculate network prefix from subnet mask
        subnet_mask = ipaddress.IPv4Address(wifi_subnet)
        prefix = bin(int(subnet_mask)).count('1')
        network = ipaddress.IPv4Network(f"{wifi_ip}/{prefix}", strict=False)

        details = f"WiFi IP Address: {wifi_ip}\n"
        details += f"Subnet Mask: {wifi_subnet}\n"
        details += f"Network: {network}\n\n"

        # Get connected Wi-Fi name (SSID)
        ssid = "Not available"
        try:
            ssid_result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
            ssid_output = ssid_result.stdout
            for line in ssid_output.split('\n'):
                if 'SSID' in line and ':' in line:
                    ssid = line.split(':')[1].strip()
                    break
        except Exception as e:
            ssid = f"Error retrieving SSID: {e}"

        details += f"Connected Wi-Fi Name (SSID): {ssid}\n\n"

        # Get connected devices by scanning the entire subnet with concurrent pings
        details += "Connected Devices (active devices on the network):\n"
        active_ips = []

        def ping_ip(ip):
            try:
                result = subprocess.run(['ping', '-n', '1', '-w', '100', str(ip)], capture_output=True, text=True)
                if result.returncode == 0:
                    return str(ip)
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(ping_ip, ip) for ip in network.hosts() if str(ip) != wifi_ip]
            for future in as_completed(futures):
                ip = future.result()
                if ip:
                    active_ips.append(ip)

        # For each active IP, get MAC from ARP
        for ip in active_ips:
            arp_result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
            arp_output = arp_result.stdout
            mac = "Unknown"
            for line in arp_output.split('\n'):
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        mac = parts[1]
                        break
            details += f"IP: {ip}, MAC: {mac}"
            if show_device_details:
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    details += f", Hostname: {hostname}"
                except:
                    details += ", Hostname: Unknown"
            details += "\n"

        return details

    except Exception as e:
        return f"Error: {e}"

def fetch_details():
    def run_in_thread():
        try:
            text_area.delete(1.0, tk.END)
            text_area.insert(tk.END, "Scanning network... Please wait.\n")
            show_details = show_details_var.get()
            details = get_wifi_details(show_details)
            text_area.delete(1.0, tk.END)
            text_area.insert(tk.END, details)
        except Exception as e:
            text_area.delete(1.0, tk.END)
            text_area.insert(tk.END, f"Error fetching details: {e}")
    threading.Thread(target=run_in_thread, daemon=True).start()

def block_device():
    if not is_admin():
        messagebox.showerror("Error", "Administrator privileges are required to block/unblock internet access. Please run the application as administrator.")
        return
    ip = ip_entry.get().strip()
    if not ip:
        messagebox.showerror("Error", "Please enter an IP address.")
        return
    try:
        # Add firewall rule to block outbound traffic for the IP
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_' + ip, 'dir=out', 'action=block', 'remoteip=' + ip], check=True)
        messagebox.showinfo("Success", f"Internet access blocked for {ip}.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to block {ip}: {e}")

def unblock_device():
    ip = ip_entry.get().strip()
    if not ip:
        messagebox.showerror("Error", "Please enter an IP address.")
        return
    try:
        # Delete the firewall rule to unblock
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_' + ip], check=True)
        messagebox.showinfo("Success", f"Internet access unblocked for {ip}.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to unblock {ip}: {e}")

# Create the main window
root = tk.Tk()
root.title("WiFi Details Tool")

# Create a checkbox for showing device details
show_details_var = tk.BooleanVar(value=True)  # Default to checked
show_details_checkbox = tk.Checkbutton(root, text="Show Device Details", variable=show_details_var)
show_details_checkbox.pack(pady=5)

# Create a button to Show details
fetch_button = tk.Button(root, text="Show WiFi Details", command=fetch_details)
fetch_button.pack(pady=10)

# Create a scrolled text area to display the details
text_area = scrolledtext.ScrolledText(root, width=80, height=20)
text_area.pack(pady=10)

# Create entry for IP address
ip_label = tk.Label(root, text="Enter IP Address to Block/Unblock:")
ip_label.pack(pady=5)
ip_entry = tk.Entry(root, width=20)
ip_entry.pack(pady=5)

# Create block and unblock buttons
block_button = tk.Button(root, text="Block Internet Access", command=block_device)
block_button.pack(pady=5)
unblock_button = tk.Button(root, text="Unblock Internet Access", command=unblock_device)
unblock_button.pack(pady=5)

# Create refresh button
refresh_button = tk.Button(root, text="Refresh System", command=fetch_details)
refresh_button.pack(pady=5)

if __name__ == "__main__":
    root.mainloop()
