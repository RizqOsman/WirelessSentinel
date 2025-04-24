import logging
import subprocess
from kamene.all import Dot11, Dot11Beacon, Dot11Elt, sniff, RadioTap
import time
import os
from threading import Thread

logger = logging.getLogger(__name__)

class NetworkScanner:
    """Class for scanning and detecting WiFi networks using an Alfa network card"""
    
    def __init__(self, interface):
        """
        Initialize the scanner with the specified interface
        
        Args:
            interface (str): The network interface to use (e.g., wlan0, wlan1)
        """
        self.interface = interface
        self.networks = {}  # Dictionary to store network information
        self.monitor_mode = False
        self.stop_sniffing = False
        
    def enable_monitor_mode(self):
        """Enable monitor mode on the interface"""
        try:
            # Check if already in monitor mode
            process = subprocess.run(
                ["iwconfig", self.interface], 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            if "Mode:Monitor" in process.stdout:
                logger.info(f"Interface {self.interface} is already in monitor mode")
                self.monitor_mode = True
                return True
                
            # Turn off the interface
            subprocess.run(
                ["sudo", "ip", "link", "set", self.interface, "down"], 
                check=True
            )
            
            # Set monitor mode
            subprocess.run(
                ["sudo", "iwconfig", self.interface, "mode", "monitor"], 
                check=True
            )
            
            # Turn on the interface
            subprocess.run(
                ["sudo", "ip", "link", "set", self.interface, "up"], 
                check=True
            )
            
            logger.info(f"Enabled monitor mode on {self.interface}")
            self.monitor_mode = True
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to enable monitor mode: {str(e)}")
            return False
            
    def disable_monitor_mode(self):
        """Disable monitor mode and return to managed mode"""
        try:
            # Turn off the interface
            subprocess.run(
                ["sudo", "ip", "link", "set", self.interface, "down"], 
                check=True
            )
            
            # Set managed mode
            subprocess.run(
                ["sudo", "iwconfig", self.interface, "mode", "managed"], 
                check=True
            )
            
            # Turn on the interface
            subprocess.run(
                ["sudo", "ip", "link", "set", self.interface, "up"], 
                check=True
            )
            
            logger.info(f"Disabled monitor mode on {self.interface}")
            self.monitor_mode = False
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to disable monitor mode: {str(e)}")
            return False
    
    def packet_handler(self, packet):
        """
        Process captured packets to extract network information
        
        Args:
            packet: The captured packet
        """
        if packet.haslayer(Dot11Beacon):
            # Extract the MAC address of the network
            bssid = packet[Dot11].addr2
            
            # Get the SSID
            try:
                ssid = packet[Dot11Elt].info.decode('utf-8')
            except:
                ssid = "Hidden SSID"
                
            # Extract signal strength from RadioTap header if available
            signal_strength = None
            if packet.haslayer(RadioTap):
                signal_strength = -(256-packet[RadioTap].dBm_AntSignal) if hasattr(packet[RadioTap], 'dBm_AntSignal') else -100
            
            # Store network information
            if bssid not in self.networks:
                self.networks[bssid] = {
                    'ssid': ssid,
                    'bssid': bssid,
                    'channel': self._get_channel(packet),
                    'signal_strength': signal_strength,
                    'security': self._get_security(packet),
                    'encryption': self._get_encryption(packet),
                    'first_seen': time.time(),
                    'last_seen': time.time()
                }
            else:
                # Update existing network info
                self.networks[bssid]['last_seen'] = time.time()
                if signal_strength is not None:
                    self.networks[bssid]['signal_strength'] = signal_strength
    
    def _get_channel(self, packet):
        """Extract channel information from the packet"""
        # Parse through Dot11Elt elements to find the channel info
        channel = None
        current_channel = 0
        
        # Look for the DS Parameter set which contains channel info
        dot11_layers = packet.getlayer(Dot11Elt)
        while dot11_layers and dot11_layers.ID != 3:
            dot11_layers = dot11_layers.payload.getlayer(Dot11Elt)
            
        if dot11_layers and dot11_layers.ID == 3 and dot11_layers.len == 1:
            channel = ord(dot11_layers.info)
            
        return channel
    
    def _get_security(self, packet):
        """Extract security information from the packet"""
        security_types = []
        
        # Check for encryption in the capabilities field
        capability = packet[Dot11Beacon].capability
        privacy_bit = capability & 0x10 > 0  # Privacy bit
        
        if not privacy_bit:
            return "Open"  # Open network
        
        # Parse through elements to determine security type
        dot11_elt = packet.getlayer(Dot11Elt)
        while dot11_elt:
            # Check for RSN (WPA2) element
            if dot11_elt.ID == 48:
                security_types.append("WPA2")
                
            # Check for vendor specific elements (could be WPA or other)
            elif dot11_elt.ID == 221 and dot11_elt.len >= 4:
                if dot11_elt.info[:4] == b"\x00\x50\xf2\x01":
                    security_types.append("WPA")
                    
            # Move to next element
            dot11_elt = dot11_elt.payload.getlayer(Dot11Elt)
        
        # If we found explicitly WPA2 or WPA, return that
        if "WPA2" in security_types:
            return "WPA2"
        elif "WPA" in security_types:
            return "WPA"
        
        # Otherwise, if privacy bit is set but no WPA/WPA2, it's probably WEP
        if privacy_bit:
            return "WEP"
            
        return "Unknown"
    
    def _get_encryption(self, packet):
        """Determine encryption type (PSK, Enterprise, etc.)"""
        # Default to unknown
        encryption = "Unknown"
        
        # Parse through elements to determine encryption type
        dot11_elt = packet.getlayer(Dot11Elt)
        while dot11_elt:
            # RSN element (WPA2)
            if dot11_elt.ID == 48 and dot11_elt.len >= 20:
                # AKM suite selectors are after the pairwise cipher suites
                # First 8 bytes: RSN IE header + version
                # Then 2 bytes for group cipher suite count
                # Then 4 bytes for the group cipher suite
                # Then 2 bytes for pairwise cipher suite count
                # Then 4*pairwise_count bytes for the pairwise cipher suites
                # Then 2 bytes for AKM suite count
                # Then 4*akm_count bytes for the AKM suites
                
                try:
                    rsn_info = dot11_elt.info
                    
                    # Skip to pairwise cipher suite count
                    offset = 8
                    
                    # Get pairwise cipher suite count and skip past it
                    if len(rsn_info) >= offset + 2:
                        pairwise_count = (rsn_info[offset] + (rsn_info[offset+1] << 8))
                        offset += 2 + (pairwise_count * 4)
                        
                        # Now we're at AKM suite count
                        if len(rsn_info) >= offset + 2:
                            akm_count = (rsn_info[offset] + (rsn_info[offset+1] << 8))
                            offset += 2
                            
                            # Parse AKM suites
                            for i in range(akm_count):
                                if len(rsn_info) >= offset + 4:
                                    akm_type = rsn_info[offset+3]  # The last byte is the type
                                    
                                    if akm_type == 1:  # 802.1X (Enterprise)
                                        return "Enterprise"
                                    elif akm_type == 2:  # PSK
                                        return "PSK"
                                    elif akm_type == 8:  # SAE (WPA3)
                                        return "SAE"
                                    
                                    offset += 4
                except Exception as e:
                    logger.debug(f"Error parsing RSN element: {str(e)}")
            
            # Move to next element
            dot11_elt = dot11_elt.payload.getlayer(Dot11Elt)
        
        return encryption
    
    def scan_networks(self, timeout=10):
        """
        Scan for WiFi networks
        
        Args:
            timeout (int): Scan duration in seconds
            
        Returns:
            list: List of detected networks
        """
        # Clear previous results
        self.networks = {}
        self.stop_sniffing = False
        
        # Enable monitor mode if not already enabled
        if not self.monitor_mode:
            if not self.enable_monitor_mode():
                logger.error("Failed to enable monitor mode. Cannot scan.")
                return []
        
        # Start sniffing in a separate thread
        logger.info(f"Starting network scan on {self.interface} for {timeout} seconds")
        sniff_thread = Thread(target=lambda: sniff(
            iface=self.interface,
            prn=self.packet_handler,
            stop_filter=lambda x: self.stop_sniffing,
            timeout=timeout
        ))
        sniff_thread.daemon = True
        sniff_thread.start()
        
        # Wait for the scan to complete
        time.sleep(timeout)
        self.stop_sniffing = True
        sniff_thread.join(2.0)  # Wait for thread to finish
        
        # Convert dictionary to list
        networks_list = list(self.networks.values())
        
        # Sort by signal strength
        networks_list.sort(key=lambda x: x['signal_strength'] if x['signal_strength'] is not None else -100, reverse=True)
        
        logger.info(f"Scan complete. Detected {len(networks_list)} networks")
        return networks_list
