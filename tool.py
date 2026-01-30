import socket
import subprocess
import ipaddress
import threading
import tkinter as tk
from tkinter import scrolledtext

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

        # Get connected devices from ARP table and verify with ping
        details += "Connected Devices (from ARP table, verified active):\n"
        arp_result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        arp_output = arp_result.stdout

        arp_devices = []
        arp_lines = arp_output.split('\n')
        for line in arp_lines:
            if line.startswith(f"{wifi_ip.split('.')[0]}.{wifi_ip.split('.')[1]}.{wifi_ip.split('.')[2]}."):  # Filter for same subnet
                parts = line.split()
                if len(parts) >= 2 and parts[0] != wifi_ip:
                    ip = parts[0]
                    mac = parts[1]
                    arp_devices.append((ip, mac))

        # Verify each ARP device with a quick ping
        active_devices = []
        for ip, mac in arp_devices:
            try:
                ping_result = subprocess.run(['ping', '-n', '1', '-w', '50', ip], capture_output=True, text=True)
                if ping_result.returncode == 0:
                    active_devices.append((ip, mac))
            except:
                pass

        # Display active devices
        for ip, mac in active_devices:
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

if __name__ == "__main__":
    root.mainloop()
