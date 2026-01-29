import socket
import subprocess
import ipaddress
import tkinter as tk
from tkinter import scrolledtext

def get_wifi_details():
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

        # Calculate network
        network = ipaddress.IPv4Network(f"{wifi_ip}/{wifi_subnet}", strict=False)

        details = f"WiFi IP Address: {wifi_ip}\n"
        details += f"Subnet Mask: {wifi_subnet}\n"
        details += f"Network: {network}\n\n"

        # Get connected devices using ARP
        arp_result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        arp_output = arp_result.stdout

        details += "Connected Devices:\n"
        arp_lines = arp_output.split('\n')
        for line in arp_lines:
            if wifi_ip.split('.')[0] in line and wifi_ip.split('.')[1] in line:  # Rough filter for same subnet
                parts = line.split()
                if len(parts) >= 2 and parts[0] != wifi_ip:
                    details += f"IP: {parts[0]}, MAC: {parts[1]}\n"

        return details

    except Exception as e:
        return f"Error: {e}"

def fetch_details():
    details = get_wifi_details()
    text_area.delete(1.0, tk.END)
    text_area.insert(tk.END, details)

# Create the main window
root = tk.Tk()
root.title("WiFi Details Tool")

# Create a button to fetch details
fetch_button = tk.Button(root, text="Fetch WiFi Details", command=fetch_details)
fetch_button.pack(pady=10)

# Create a scrolled text area to display the details
text_area = scrolledtext.ScrolledText(root, width=80, height=20)
text_area.pack(pady=10)

if __name__ == "__main__":
    root.mainloop()
