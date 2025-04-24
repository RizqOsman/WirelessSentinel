import logging
import subprocess
import re
import os
import platform
import tempfile

logger = logging.getLogger(__name__)

def get_wifi_interfaces():
    """
    Get available WiFi interfaces on the system
    
    Returns:
        list: List of wireless interface names
    """
    interfaces = []
    
    try:
        # Check if we're on Linux
        if platform.system() == "Linux":
            # Method 1: Check /sys/class/net directory
            for iface in os.listdir('/sys/class/net/'):
                # Check if it's a wireless interface
                if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                    interfaces.append(iface)
            
            # If no interfaces found, try iwconfig
            if not interfaces:
                process = subprocess.run(["iwconfig"], capture_output=True, text=True)
                for line in process.stdout.split('\n'):
                    match = re.search(r'^(\w+)', line)
                    if match and "no wireless extensions" not in line:
                        interfaces.append(match.group(1))
            
            # If still no interfaces, try ip link
            if not interfaces:
                process = subprocess.run(["ip", "link"], capture_output=True, text=True)
                for line in process.stdout.split('\n'):
                    match = re.search(r'^\d+:\s+(\w+):', line)
                    if match and (match.group(1).startswith('wlan') or 
                                match.group(1).startswith('wlp') or 
                                'wl' in match.group(1)):
                        interfaces.append(match.group(1))
                        
        # Check if we're on macOS
        elif platform.system() == "Darwin":
            process = subprocess.run(["networksetup", "-listallhardwareports"], 
                                    capture_output=True, text=True)
            for i, line in enumerate(process.stdout.split('\n')):
                if "Wi-Fi" in line or "AirPort" in line:
                    # The interface name is on the next line after "Device: "
                    match = re.search(r'Device:\s+(\w+)', process.stdout.split('\n')[i+1])
                    if match:
                        interfaces.append(match.group(1))
        
        # Check if we're on Windows
        elif platform.system() == "Windows":
            # On Windows, we'll use netsh
            process = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"], 
                capture_output=True, 
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            # Extract interface names using regex
            for line in process.stdout.split('\n'):
                match = re.search(r'Name\s+:\s+(.+)', line)
                if match:
                    interfaces.append(match.group(1).strip())
        
        # Prefer interfaces with "alfa" in the name
        alfa_interfaces = [iface for iface in interfaces if "alfa" in iface.lower()]
        if alfa_interfaces:
            # Move Alfa interfaces to the front of the list
            for alfa_iface in reversed(alfa_interfaces):
                interfaces.remove(alfa_iface)
                interfaces.insert(0, alfa_iface)
        
        return interfaces
    
    except Exception as e:
        logger.error(f"Error getting WiFi interfaces: {str(e)}")
        return []

def get_channel_for_bssid(interface, bssid):
    """
    Get the channel for a specific BSSID
    
    Args:
        interface (str): Wireless interface to use
        bssid (str): BSSID to look for
    
    Returns:
        int: Channel number if found, None otherwise
    """
    try:
        # Try different methods to get channel information
        
        # Method 1: Use iwlist (Linux)
        if platform.system() == "Linux":
            process = subprocess.run(
                ["sudo", "iwlist", interface, "scan"], 
                capture_output=True, 
                text=True
            )
            
            lines = process.stdout.split('\n')
            current_bssid = None
            
            for line in lines:
                # Look for Cell line which contains the BSSID
                if "Cell" in line and "Address:" in line:
                    current_bssid = line.split("Address:")[1].strip()
                
                # If we're on the right BSSID and found channel info
                if current_bssid and current_bssid.lower() == bssid.lower() and "Channel:" in line:
                    channel = int(line.split("Channel:")[1].strip())
                    return channel
        
        # Method 2: Use airport (macOS)
        elif platform.system() == "Darwin":
            # Use airport command line utility
            airport_cmd = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            
            if os.path.exists(airport_cmd):
                process = subprocess.run(
                    [airport_cmd, "-s"], 
                    capture_output=True, 
                    text=True
                )
                
                lines = process.stdout.split('\n')
                for line in lines:
                    fields = line.strip().split()
                    if len(fields) >= 2 and fields[1].lower() == bssid.lower():
                        # Channel is typically in field 3
                        try:
                            return int(fields[3])
                        except (IndexError, ValueError):
                            return None
        
        # Method 3: Scan with a temporary file
        # This is a fallback that works on most systems
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            # Use airodump-ng to scan for a short time
            scan_process = subprocess.Popen(
                [
                    "sudo", "timeout", "5", "airodump-ng",
                    "--output-format", "csv",
                    "-w", temp_path,
                    interface
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Wait for scan to complete
            scan_process.wait()
            
            # Read the CSV file
            csv_path = f"{temp_path}-01.csv"
            if os.path.exists(csv_path):
                with open(csv_path, 'r') as f:
                    lines = f.readlines()
                
                # Process the CSV data
                for line in lines:
                    if bssid.lower() in line.lower():
                        # Parse the line to extract channel
                        parts = line.split(',')
                        if len(parts) >= 4:
                            try:
                                return int(parts[3].strip())
                            except ValueError:
                                continue
        finally:
            # Clean up temporary files
            for ext in ["-01.csv", "-01.kismet.csv", "-01.kismet.netxml", "-01.cap"]:
                csv_path = f"{temp_path}{ext}"
                if os.path.exists(csv_path):
                    os.remove(csv_path)
        
        # If all methods fail, return None
        logger.warning(f"Could not determine channel for BSSID {bssid}")
        return None
    
    except Exception as e:
        logger.error(f"Error getting channel for BSSID: {str(e)}")
        return None

def is_root():
    """
    Check if the script is running with root/admin privileges
    
    Returns:
        bool: True if running as root/admin, False otherwise
    """
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def get_security_level_color(security_level):
    """
    Get bootstrap color class based on security level
    
    Args:
        security_level (str): Security level (High, Medium, Low)
        
    Returns:
        str: Bootstrap color class
    """
    if security_level == "High":
        return "success"
    elif security_level == "Medium":
        return "warning"
    elif security_level == "Low":
        return "danger"
    else:
        return "secondary"

def format_mac_address(mac):
    """
    Format MAC address for display
    
    Args:
        mac (str): MAC address
        
    Returns:
        str: Formatted MAC address
    """
    if not mac:
        return ""
    
    # Remove any non-hex characters
    mac = re.sub(r'[^0-9a-fA-F]', '', mac)
    
    # Format as XX:XX:XX:XX:XX:XX
    if len(mac) == 12:
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))
    
    return mac
