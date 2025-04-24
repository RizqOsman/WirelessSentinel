import logging

logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    """Analyzes the security level of detected WiFi networks"""
    
    def __init__(self):
        """Initialize the security analyzer"""
        # Define security rankings (higher is better)
        self.security_rankings = {
            "Open": 0,
            "WEP": 1,
            "WPA": 2,
            "WPA2": 3,
            "WPA3": 4,
            "Unknown": 0
        }
        
        # Define encryption rankings (higher is better)
        self.encryption_rankings = {
            "Unknown": 0,
            "TKIP": 1,
            "CCMP": 2,
            "PSK": 2,
            "Enterprise": 3,
            "SAE": 4
        }
    
    def analyze_network(self, network):
        """
        Analyze the security level of a network
        
        Args:
            network (dict): Network information dictionary
            
        Returns:
            dict: Security analysis results
        """
        # Default values
        security_score = 0
        security_level = "Unknown"
        is_secure = False
        is_weak = False
        alerts = []
        
        # Extract security info from network
        security_type = network.get('security', 'Unknown')
        encryption_type = network.get('encryption', 'Unknown')
        
        # Calculate security score
        security_score = self.security_rankings.get(security_type, 0)
        security_score += self.encryption_rankings.get(encryption_type, 0)
        
        # Determine security level based on score
        if security_score >= 5:
            security_level = "High"
            is_secure = True
        elif security_score >= 3:
            security_level = "Medium"
            is_secure = True
        else:
            security_level = "Low"
            is_weak = True
            alerts.append("Alert (Not Secure)")
        
        # Special case checks
        if security_type == "Open":
            alerts.append("Open Network - No Encryption")
            
        elif security_type == "WEP":
            alerts.append("WEP is deprecated and easily crackable")
            
        elif security_type == "WPA":
            alerts.append("WPA is outdated and vulnerable to attacks")
            
        elif security_type == "WPA2" and encryption_type == "TKIP":
            alerts.append("TKIP encryption has known vulnerabilities")
            
        # Check for hidden SSIDs (could be suspicious)
        if network.get('ssid') == "Hidden SSID":
            alerts.append("Hidden SSID (Note: Hiding SSID is not a security measure)")
        
        # Return analysis results
        return {
            'security_score': security_score,
            'security_level': security_level,
            'is_secure': is_secure,
            'is_weak': is_weak,
            'alerts': alerts
        }
        
    def get_vulnerable_networks(self, networks):
        """
        Filter networks to return only vulnerable ones
        
        Args:
            networks (list): List of network dictionaries
            
        Returns:
            list: Filtered list of vulnerable networks
        """
        vulnerable = []
        
        for network in networks:
            # Analyze the network
            analysis = self.analyze_network(network)
            
            # If it's weak, add it to the vulnerable list
            if analysis['is_weak']:
                vulnerable.append({**network, **analysis})
                
        return vulnerable
