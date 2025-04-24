import logging
from kamene.all import Dot11, Dot11Deauth, sniff
from threading import Thread
import time

logger = logging.getLogger(__name__)

class DeauthDetector:
    """Detects deauthentication attacks which could indicate rogue access points"""
    
    def __init__(self):
        """Initialize the deauth detector"""
        self.deauth_events = {}  # Dictionary to track deauth events
        self.deauth_threshold = 10  # Number of deauth packets to consider as an attack
        self.time_window = 60  # Time window in seconds to consider packets part of the same attack
        self.stop_sniffing = False
        self.active_thread = None
    
    def packet_handler(self, packet):
        """
        Process packets to detect deauthentication frames
        
        Args:
            packet: The captured packet
        """
        # Check if it's a deauthentication packet
        if packet.haslayer(Dot11Deauth):
            # Get the BSSID (AP MAC address)
            if packet.haslayer(Dot11):
                bssid = packet[Dot11].addr3
                # Get client MAC if available
                client_mac = packet[Dot11].addr1 if packet[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else "broadcast"
                
                # Create a key for this deauth event
                event_key = f"{bssid}_{client_mac}"
                
                current_time = time.time()
                
                # Create or update the deauth event
                if event_key in self.deauth_events:
                    event = self.deauth_events[event_key]
                    # Check if it's within the time window
                    if current_time - event['last_seen'] <= self.time_window:
                        # Update the count and timestamp
                        event['count'] += 1
                        event['last_seen'] = current_time
                    else:
                        # Start a new event
                        self.deauth_events[event_key] = {
                            'bssid': bssid,
                            'client_mac': client_mac,
                            'count': 1,
                            'first_seen': current_time,
                            'last_seen': current_time
                        }
                else:
                    # New deauth event
                    self.deauth_events[event_key] = {
                        'bssid': bssid,
                        'client_mac': client_mac,
                        'count': 1,
                        'first_seen': current_time,
                        'last_seen': current_time
                    }
    
    def detect_deauth(self, interface, duration=30):
        """
        Start monitoring for deauthentication frames
        
        Args:
            interface (str): Network interface to monitor
            duration (int): Duration in seconds to monitor
            
        Returns:
            list: Detected rogue access points
        """
        # Clear previous results
        self.deauth_events = {}
        self.stop_sniffing = False
        
        # Start sniffing in a separate thread
        logger.info(f"Starting deauth detection on {interface} for {duration} seconds")
        sniff_thread = Thread(target=lambda: sniff(
            iface=interface,
            filter="type mgt subtype deauth",
            prn=self.packet_handler,
            stop_filter=lambda x: self.stop_sniffing,
            timeout=duration
        ))
        sniff_thread.daemon = True
        sniff_thread.start()
        
        # Set as active thread
        self.active_thread = sniff_thread
        
        # Wait for the monitoring to complete
        time.sleep(duration)
        self.stop_sniffing = True
        sniff_thread.join(2.0)  # Wait for thread to finish
        
        # Identify potential rogue APs based on deauth patterns
        rogue_aps = []
        
        for key, event in self.deauth_events.items():
            # If we see a significant number of deauth packets, flag as potential rogue AP
            if event['count'] >= self.deauth_threshold:
                rogue_aps.append({
                    'bssid': event['bssid'],
                    'client_mac': event['client_mac'],
                    'deauth_count': event['count'],
                    'detection_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event['first_seen'])),
                    'alert': "Potential Rogue AP - Deauthentication Attack Detected"
                })
        
        logger.info(f"Deauth detection complete. Found {len(rogue_aps)} potential rogue APs")
        return rogue_aps
    
    def stop_detection(self):
        """Stop the ongoing detection"""
        self.stop_sniffing = True
        if self.active_thread and self.active_thread.is_alive():
            self.active_thread.join(2.0)
        logger.info("Deauth detection stopped")
