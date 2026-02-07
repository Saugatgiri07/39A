import socket
import subprocess
import ipaddress
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor, as_completed
import ctypes
import sys
import os
import re
import logging
import csv
import time
from datetime import datetime, timedelta
import argparse

# Setup logging
logging.basicConfig(filename='network_jammer.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

active_ips = []
block_all_used = False  # Flag to track if Block All was used

def validate_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def check_blocked(ip):
    try:
        # Check if outbound block rule exists
        result_out = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name=Block_Out_{ip}'], capture_output=True, text=True)
        # Check if inbound block rule exists
        result_in = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name=Block_In_{ip}'], capture_output=True, text=True)
        if 'No rules match the specified criteria' not in result_out.stdout and 'No rules match the specified criteria' not in result_in.stdout:
            return "Blocked"
        else:
            return "Unblocked"
    except Exception as e:
        return f"Unknown ({e})"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()
    else:
        messagebox.showinfo("Info", "Application is already running with administrator privileges.")

def get_wifi_details(show_device_details=False):
    try:
        # Run ipconfig to get network details
        result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
        output = result.stdout

        # Find WiFi adapter section
        lines = output.split('\n')
        wifi_ip = None
        wifi_subnet = None
        in_wifi_section = False

        for line in lines:
            line = line.strip()
            if re.search(r'Wireless LAN adapter|Wi-Fi|Wireless.*adapter', line, re.IGNORECASE):
                in_wifi_section = True
            elif re.search(r'adapter', line, re.IGNORECASE) and not re.search(r'Wi-Fi|Wireless', line, re.IGNORECASE):
                in_wifi_section = False
            elif in_wifi_section:
                if re.search(r'IPv4 Address|IP Address', line, re.IGNORECASE):
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        wifi_ip = ip_match.group(1)
                elif re.search(r'Subnet Mask', line, re.IGNORECASE):
                    subnet_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if subnet_match:
                        wifi_subnet = subnet_match.group(1)

        if not wifi_ip or not wifi_subnet:
            # Debug: show what we found
            debug_info = f"Debug: wifi_ip={wifi_ip}, wifi_subnet={wifi_subnet}\n"
            debug_info += "Full ipconfig output:\n" + output
            return f"Could not find WiFi IP or subnet. Ensure you are connected to WiFi.\n\n{debug_info}"

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

        # Get connected devices by scanning the subnet more efficiently
        details += "Connected Devices (active devices on the network):\n"
        global active_ips
        active_ips = []

        def ping_ip(ip):
            try:
                # Improved ping with 2 attempts and 1000ms timeout for better accuracy
                result = subprocess.run(['ping', '-n', '2', '-w', '1000', str(ip)], capture_output=True, text=True)
                if 'Reply from' in result.stdout:
                    return str(ip)
            except:
                pass
            return None

        # Scan expanded range for better accuracy
        base_ip = ipaddress.IPv4Address(wifi_ip)
        start_ip = max(ipaddress.IPv4Address(network.network_address) + 1, base_ip - 20)
        end_ip = min(ipaddress.IPv4Address(network.broadcast_address) - 1, base_ip + 100)

        scan_ips = [ip for ip in network.hosts() if start_ip <= ip <= end_ip and str(ip) != wifi_ip]

        with ThreadPoolExecutor(max_workers=30) as executor:  # Increased workers for better performance
            futures = [executor.submit(ping_ip, ip) for ip in scan_ips]
            for future in as_completed(futures):
                ip = future.result()
                if ip:
                    active_ips.append(ip)

        details += f"Total connected devices: {len(active_ips)}\n\n"

        # For each active IP, get MAC from ARP and device name concurrently
        def get_device_info(ip):
            arp_result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
            arp_output = arp_result.stdout
            mac = "Unknown"
            for line in arp_output.split('\n'):
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        mac = parts[1]
                        break
            device_name = "Unknown"
            try:
                # Try to get fully qualified domain name
                device_name = socket.getfqdn(ip)
                if device_name == ip:
                    device_name = "Unknown"
            except:
                pass
            if device_name == "Unknown":
                try:
                    # Try nslookup for DNS name
                    nslookup_result = subprocess.run(['nslookup', ip], capture_output=True, text=True, timeout=5)
                    nslookup_output = nslookup_result.stdout
                    for line in nslookup_output.split('\n'):
                        if 'Name:' in line:
                            device_name = line.split('Name:')[1].strip()
                            break
                except:
                    pass
            if device_name == "Unknown":
                try:
                    # Try to get NetBIOS name using nbtstat
                    nbt_result = subprocess.run(['nbtstat', '-a', ip], capture_output=True, text=True, timeout=5)
                    nbt_output = nbt_result.stdout
                    for line in nbt_output.split('\n'):
                        if '<00>' in line and 'UNIQUE' in line:
                            parts = line.split()
                            if len(parts) > 0:
                                device_name = parts[0].strip()
                                break
                except:
                    pass
            if device_name == "Unknown":
                try:
                    # Fallback to reverse DNS lookup
                    device_name = socket.gethostbyaddr(ip)[0]
                except:
                    pass
            if device_name == "Unknown":
                try:
                    # Try ping with -a to resolve hostname
                    ping_result = subprocess.run(['ping', '-a', '-n', '1', '-w', '1000', ip], capture_output=True, text=True)
                    ping_output = ping_result.stdout
                    for line in ping_output.split('\n'):
                        if 'Pinging' in line and '[' in line:
                            start = line.find('Pinging') + 8
                            end = line.find('[')
                            if start < end:
                                device_name = line[start:end].strip()
                                break
                except:
                    pass
            status = check_blocked(ip)
            return f"IP: {ip}, MAC: {mac}, Device Name: {device_name}, Status: {status}\n"

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(get_device_info, ip) for ip in active_ips]
            for future in as_completed(futures):
                details += future.result()

        return details

    except Exception as e:
        return f"Error: {e}"

def clear_details():
    text_area.delete(1.0, tk.END)

def fetch_details():
    def run_in_thread():
        try:
            # Disable buttons during scanning
            fetch_button.config(state=tk.DISABLED)
            refresh_button.config(state=tk.DISABLED)
            block_button.config(state=tk.DISABLED)
            unblock_button.config(state=tk.DISABLED)
            block_all_button.config(state=tk.DISABLED)
            if block_all_used:
                unblock_all_button.config(state=tk.DISABLED)

            text_area.delete(1.0, tk.END)
            text_area.insert(tk.END, "Scanning network... Please wait.\n")
            root.update_idletasks()  # Make GUI responsive
            show_details = show_details_var.get()
            details = get_wifi_details(show_details)
            text_area.delete(1.0, tk.END)
            text_area.insert(tk.END, details)
        except Exception as e:
            text_area.delete(1.0, tk.END)
            text_area.insert(tk.END, f"Error fetching details: {e}")
        finally:
            # Re-enable buttons
            fetch_button.config(state=tk.NORMAL)
            refresh_button.config(state=tk.NORMAL)
            block_button.config(state=tk.NORMAL)
            unblock_button.config(state=tk.NORMAL)
            block_all_button.config(state=tk.NORMAL)
            if block_all_used:
                unblock_all_button.config(state=tk.NORMAL)
    threading.Thread(target=run_in_thread, daemon=True).start()

def block_device():
    if not is_admin():
        messagebox.showerror("Error", "Administrator privileges are required to block/unblock communication. Please run the application as administrator.")
        return
    ip = ip_entry.get().strip()
    if not ip:
        messagebox.showerror("Error", "Please enter an IP address.")
        return
    if not validate_ip(ip):
        messagebox.showerror("Error", "Invalid IP address format.")
        return
    duration = duration_entry.get().strip()
    if duration:
        try:
            duration_sec = int(duration) * 60  # minutes to seconds
        except ValueError:
            messagebox.showerror("Error", "Invalid duration. Enter minutes as a number.")
            return
    else:
        duration_sec = None
    try:
        # Force block: delete any existing rules first
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_Out_' + ip], capture_output=True, shell=True)
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_In_' + ip], capture_output=True, shell=True)
        # Add firewall rules to block all inbound and outbound traffic to/from the IP
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_Out_' + ip, 'dir=out', 'action=block', 'remoteip=' + ip, 'protocol=any'], check=True, shell=True)
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_In_' + ip, 'dir=in', 'action=block', 'remoteip=' + ip, 'protocol=any'], check=True, shell=True)
        # Also block specific protocols for thoroughness
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_TCP_' + ip, 'dir=out', 'action=block', 'remoteip=' + ip, 'protocol=TCP'], check=True, shell=True)
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_UDP_' + ip, 'dir=out', 'action=block', 'remoteip=' + ip, 'protocol=UDP'], check=True, shell=True)
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_TCP_In_' + ip, 'dir=in', 'action=block', 'remoteip=' + ip, 'protocol=TCP'], check=True, shell=True)
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_UDP_In_' + ip, 'dir=in', 'action=block', 'remoteip=' + ip, 'protocol=UDP'], check=True, shell=True)
        # Add ICMP blocking for more thorough blocking
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_ICMP_Out_' + ip, 'dir=out', 'action=block', 'remoteip=' + ip, 'protocol=icmpv4'], check=True, shell=True)
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_ICMP_In_' + ip, 'dir=in', 'action=block', 'remoteip=' + ip, 'protocol=icmpv4'], check=True, shell=True)
        logging.info(f"Blocked IP: {ip}")
        if duration_sec:
            threading.Timer(duration_sec, lambda: unblock_device_auto(ip)).start()
            messagebox.showinfo("Success", f"Communication blocked with {ip} for {duration} minutes.")
        else:
            messagebox.showinfo("Success", f"Communication blocked with {ip}.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to block {ip}: {e}")
        logging.error(f"Failed to block {ip}: {e}")

def unblock_device_auto(ip):
    try:
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_Out_' + ip], check=True, shell=True)
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_In_' + ip], check=True, shell=True)
        logging.info(f"Auto-unblocked IP: {ip}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to auto-unblock {ip}: {e}")

def unblock_device():
    ip = ip_entry.get().strip()
    if not ip:
        messagebox.showerror("Error", "Please enter an IP address.")
        return
    if not validate_ip(ip):
        messagebox.showerror("Error", "Invalid IP address format.")
        return
    try:
        # Delete the firewall rules to unblock
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_Out_' + ip], check=True, shell=True)
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_In_' + ip], check=True, shell=True)
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_All_' + ip], check=True, shell=True)
        # Also delete ICMP rules
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_ICMP_Out_' + ip], check=True, shell=True)
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_ICMP_In_' + ip], check=True, shell=True)
        logging.info(f"Unblocked IP: {ip}")
        messagebox.showinfo("Success", f"Internet access unblocked for {ip}.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to unblock {ip}: {e}")
        logging.error(f"Failed to unblock {ip}: {e}")

def block_all_devices():
    if not is_admin():
        messagebox.showerror("Error", "Administrator privileges are required to block/unblock internet access. Please run the application as administrator.")
        return
    if not active_ips:
        messagebox.showerror("Error", "No connected devices found. Please scan the network first.")
        return
    try:
        for ip in active_ips:
            # Add firewall rules to block both inbound and outbound traffic for each IP
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_Out_' + ip, 'dir=out', 'action=block', 'remoteip=' + ip], check=True, shell=True)
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_In_' + ip, 'dir=in', 'action=block', 'remoteip=' + ip], check=True, shell=True)
        global block_all_used
        block_all_used = True
        messagebox.showinfo("Success", f"Internet access blocked for all connected devices ({len(active_ips)} devices).")
        unblock_all_button.pack(pady=5)  # Show the unblock all button
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to block all devices: {e}")

def unblock_all_devices():
    if not active_ips:
        messagebox.showerror("Error", "No connected devices found.")
        return
    try:
        for ip in active_ips:
            # Delete the firewall rules to unblock
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_Out_' + ip], check=True, shell=True)
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_In_' + ip], check=True, shell=True)
        messagebox.showinfo("Success", f"Internet access unblocked for all connected devices ({len(active_ips)} devices).")
        unblock_all_button.pack_forget()  # Hide the unblock all button
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to unblock all devices: {e}")

def export_devices():
    if not active_ips:
        messagebox.showerror("Error", "No connected devices found. Please scan the network first.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return
    try:
        with open(file_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['IP Address', 'MAC Address', 'Device Name', 'Status'])
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
                device_name = "Unknown"
                try:
                    device_name = socket.getfqdn(ip)
                    if device_name == ip:
                        device_name = "Unknown"
                except:
                    pass
                status = check_blocked(ip)
                writer.writerow([ip, mac, device_name, status])
        messagebox.showinfo("Success", f"Device list exported to {file_path}")
        logging.info(f"Exported device list to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to export: {e}")
        logging.error(f"Failed to export device list: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Jammer Tool")
    parser.add_argument('--scan', action='store_true', help='Scan network and print details')
    parser.add_argument('--block', type=str, help='Block IP address')
    parser.add_argument('--unblock', type=str, help='Unblock IP address')
    parser.add_argument('--block-all', action='store_true', help='Block all devices')
    parser.add_argument('--unblock-all', action='store_true', help='Unblock all devices')

    args = parser.parse_args()

    if args.scan:
        if not is_admin():
            print("Administrator privileges required.")
            sys.exit(1)
        print(get_wifi_details(show_device_details=True))
        sys.exit()

    if args.block:
        if not is_admin():
            print("Administrator privileges required.")
            sys.exit(1)
        if not validate_ip(args.block):
            print("Invalid IP address.")
            sys.exit(1)
        try:
            # Simplified block for CLI
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_Out_' + args.block, 'dir=out', 'action=block', 'remoteip=' + args.block], check=True, shell=True)
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_In_' + args.block, 'dir=in', 'action=block', 'remoteip=' + args.block], check=True, shell=True)
            print(f"Blocked {args.block}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to block {args.block}: {e}")
        sys.exit()

    if args.unblock:
        if not is_admin():
            print("Administrator privileges required.")
            sys.exit(1)
        if not validate_ip(args.unblock):
            print("Invalid IP address.")
            sys.exit(1)
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_Out_' + args.unblock], check=True, shell=True)
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_In_' + args.unblock], check=True, shell=True)
            print(f"Unblocked {args.unblock}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to unblock {args.unblock}: {e}")
        sys.exit()

    if args.block_all:
        if not is_admin():
            print("Administrator privileges required.")
            sys.exit(1)
        # First scan
        get_wifi_details(show_device_details=False)
        if not active_ips:
            print("No devices found.")
            sys.exit(1)
        try:
            for ip in active_ips:
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_Out_' + ip, 'dir=out', 'action=block', 'remoteip=' + ip], check=True, shell=True)
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=Block_In_' + ip, 'dir=in', 'action=block', 'remoteip=' + ip], check=True, shell=True)
            print(f"Blocked all {len(active_ips)} devices")
        except subprocess.CalledProcessError as e:
            print(f"Failed to block all: {e}")
        sys.exit()

    if args.unblock_all:
        if not is_admin():
            print("Administrator privileges required.")
            sys.exit(1)
        # First scan
        get_wifi_details(show_device_details=False)
        if not active_ips:
            print("No devices found.")
            sys.exit(1)
        try:
            for ip in active_ips:
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_Out_' + ip], check=True, shell=True)
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=Block_In_' + ip], check=True, shell=True)
            print(f"Unblocked all {len(active_ips)} devices")
        except subprocess.CalledProcessError as e:
            print(f"Failed to unblock all: {e}")
        sys.exit()

    # GUI mode - admin check is handled in blocking functions for better usability

    # GUI mode
    print("Starting Network Jammer GUI...")

    # Create the main window
    root = tk.Tk()
    root.title("Network Jammer")
    # root.attributes("-topmost", True)  # Temporarily comment out for testing
    root.configure(bg='#f0f0f0')
    root.update()
    print("GUI window created successfully.")

    # Create a checkbox for showing device details
    show_details_var = tk.BooleanVar(value=True)  # Default to checked
    show_details_checkbox = tk.Checkbutton(root, text="Show Device Details", variable=show_details_var, bg='#f0f0f0')
    show_details_checkbox.pack(pady=5)

    # Create a button to run as administrator
    admin_button = tk.Button(root, text="Run as Administrator", command=run_as_admin, bg='#4CAF50', fg='white')
    admin_button.pack(pady=5)

    # Create a button to Show details
    fetch_button = tk.Button(root, text="Scan Network", command=fetch_details, bg='#2196F3', fg='white')
    fetch_button.pack(pady=10)

    # Create a scrolled text area to display the details
    text_area = scrolledtext.ScrolledText(root, width=80, height=20, bg='#ffffff', fg='#000000')
    text_area.pack(pady=10)

    # Create clear details button
    clear_button = tk.Button(root, text="Clear Details", command=clear_details, bg='#FF9800', fg='white')
    clear_button.pack(pady=5)

    # Create entry for IP address
    ip_label = tk.Label(root, text="Enter IP Address to Block/Unblock:", bg='#f0f0f0')
    ip_label.pack(pady=5)
    ip_entry = tk.Entry(root, width=20)
    ip_entry.pack(pady=5)

    # Create entry for duration
    duration_label = tk.Label(root, text="Block Duration (minutes, optional):", bg='#f0f0f0')
    duration_label.pack(pady=5)
    duration_entry = tk.Entry(root, width=20)
    duration_entry.pack(pady=5)

    # Create block and unblock buttons
    block_button = tk.Button(root, text="Block Internet Access", command=block_device, bg='#F44336', fg='white')
    block_button.pack(pady=5)
    unblock_button = tk.Button(root, text="Unblock Internet Access", command=unblock_device, bg='#4CAF50', fg='white')
    unblock_button.pack(pady=5)

    # Create refresh button
    refresh_button = tk.Button(root, text="Refresh Details", command=fetch_details, bg='#2196F3', fg='white')
    refresh_button.pack(pady=5)

    # Create block all devices button
    block_all_button = tk.Button(root, text="Block All Internet Access", command=block_all_devices, bg='#F44336', fg='white')
    block_all_button.pack(pady=5)

    # Create unblock all devices button (initially hidden)
    unblock_all_button = tk.Button(root, text="Unblock All Internet Access", command=unblock_all_devices, bg='#4CAF50', fg='white')

    # Create export button
    export_button = tk.Button(root, text="Export Device List", command=export_devices, bg='#9C27B0', fg='white')
    export_button.pack(pady=5)

    root.mainloop()
