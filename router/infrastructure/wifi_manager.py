"""
WiFi Access Point Manager
Handles creation and management of WiFi access points using NetworkManager
"""

import subprocess
import time
import os
from typing import Optional, Dict, Any

from core.config import RouterConfig
from core.logger import get_logger
from infrastructure.dhcp_server import DHCPServerManager


class WiFiAccessPointManager:
    """
    Manages WiFi Access Point setup and teardown using NetworkManager
    """
    
    def __init__(self, config: RouterConfig):
        self.config = config
        self.logger = get_logger(__name__)
        
        # Connection settings
        self.connection_name = f"IoT-AP-{config.router_id}"
        self.ssid = config.router_id
        self.password = config.shared_secret
        
        # Network settings
        self.ip_address = config.wifi.server_host
        self.subnet = "192.168.50.0/24"
        self.interface = self._detect_wifi_interface()
        
        # Initialize DHCP server manager
        self.dhcp_server = DHCPServerManager(config)
        
        self.logger.info("WiFi AP Manager initialized",
                        connection_name=self.connection_name,
                        ssid=self.ssid,
                        interface=self.interface)
    
    def setup_hotspot(self) -> bool:
        """
        Setup WiFi hotspot using NetworkManager with dedicated DHCP server
        Returns True if successful
        """
        try:
            self.logger.info("Setting up WiFi Access Point...")
            
            # Check if we're running as root
            if os.geteuid() != 0:
                self.logger.error("Root privileges required for WiFi AP setup")
                return False
            
            # Remove existing connection if it exists
            self._remove_existing_connection()
            
            # Create new hotspot connection first
            if not self._create_hotspot_connection():
                return False
            
            # Wait a moment for connection to be ready
            time.sleep(2)
            
            # Activate the connection to create the interface
            if not self._activate_connection():
                return False
            
            # Wait for interface to be fully up
            time.sleep(3)
            
            # Now setup DHCP server after WiFi interface is created
            self.logger.info("Setting up DHCP server...")
            if not self.dhcp_server.setup_dhcp_server():
                self.logger.error("Failed to setup DHCP server")
                # Cleanup and return error
                self._deactivate_connection()
                self._remove_existing_connection()
                return False
            
            # Verify the connection is working
            if self._verify_hotspot():
                self.logger.info("WiFi Access Point setup successful",
                               ssid=self.ssid,
                               ip_address=self.ip_address,
                               dhcp_enabled=True)
                return True
            else:
                self.logger.error("WiFi Access Point verification failed")
                self.dhcp_server.teardown_dhcp_server()  # Cleanup on failure
                return False
                
        except Exception as e:
            self.logger.error(f"Error setting up WiFi hotspot: {e}", exc_info=True)
            # Cleanup on exception
            try:
                self.dhcp_server.teardown_dhcp_server()
            except Exception:
                pass
            return False
    
    def teardown_hotspot(self) -> bool:
        """
        Teardown WiFi hotspot and DHCP server
        Returns True if successful
        """
        try:
            self.logger.info("Tearing down WiFi Access Point...")
            
            # Deactivate connection
            self._deactivate_connection()
            
            # Remove connection
            self._remove_existing_connection()
            
            # Teardown DHCP server
            self.logger.info("Tearing down DHCP server...")
            dhcp_success = self.dhcp_server.teardown_dhcp_server()
            if not dhcp_success:
                self.logger.warning("DHCP server teardown had issues but continuing")
            
            self.logger.info("WiFi Access Point torn down successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error tearing down WiFi hotspot: {e}")
            # Try to cleanup DHCP server even if other teardown failed
            try:
                self.dhcp_server.teardown_dhcp_server()
            except Exception:
                pass
            return False
    
    def _detect_wifi_interface(self) -> str:
        """
        Detect available WiFi interface
        Returns interface name, defaults to wlan0 if detection fails
        """
        try:
            # Get wireless interfaces
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Parse iw output to find interface names
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Interface' in line:
                        interface = line.split('Interface')[1].strip()
                        self.logger.debug(f"Found WiFi interface: {interface}")
                        return interface
            
            # Fallback: check common interface names
            for iface in ['wlan0', 'wlp3s0', 'wlx*', 'wifi0']:
                result = subprocess.run(["ip", "link", "show", iface], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    self.logger.debug(f"Using WiFi interface: {iface}")
                    return iface
            
            # Final fallback
            self.logger.warning("Could not detect WiFi interface, using wlan0")
            return "wlan0"
            
        except Exception as e:
            self.logger.warning(f"Error detecting WiFi interface: {e}, using wlan0")
            return "wlan0"
    
    def _remove_existing_connection(self):
        """Remove existing connection with the same name"""
        try:
            cmd = ["nmcli", "connection", "delete", self.connection_name]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.debug(f"Removed existing connection: {self.connection_name}")
            else:
                # Connection might not exist, which is fine
                self.logger.debug(f"No existing connection to remove: {self.connection_name}")
                
        except Exception as e:
            self.logger.debug(f"Error removing existing connection: {e}")
    
    def _create_hotspot_connection(self) -> bool:
        """Create NetworkManager hotspot connection with manual IP configuration"""
        try:
            # Build nmcli command for creating hotspot
            # Using manual IPv4 method since we have our own DHCP server
            cmd = [
                "nmcli", "connection", "add",
                "type", "wifi",
                "ifname", self.interface,
                "con-name", self.connection_name,
                "autoconnect", "no",
                "wifi.mode", "ap",
                "wifi.ssid", self.ssid,
                "wifi.band", "bg",
                "wifi.channel", str(self.config.wifi.channel),
                "wifi-sec.key-mgmt", "wpa-psk",
                "wifi-sec.psk", self.password,
                "wifi-sec.proto", "rsn",  # Force WPA2 (RSN)
                "wifi-sec.pairwise", "ccmp",  # Use AES-CCMP encryption
                "wifi-sec.group", "ccmp",  # Use AES-CCMP for group
                "wifi-sec.wps-method", "disabled",  # Disable WPS
                "wifi-sec.pmf", "default",  # Protected Management Frames
                "ipv4.method", "manual",  # Manual IP (we handle DHCP separately)
                "ipv4.address", f"{self.ip_address}/24",
                "ipv4.gateway", self.ip_address,
                "ipv4.dns", self.ip_address
            ]
            
            self.logger.debug("Creating hotspot connection", command=" ".join(cmd))
            self.logger.info("Configuring WiFi AP with WPA2-PSK + AES-CCMP security (WPS disabled)")
            self.logger.info("Using manual IP configuration with dedicated DHCP server")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.logger.info("Hotspot connection created successfully")
                return True
            else:
                self.logger.error(f"Failed to create hotspot connection: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout creating hotspot connection")
            return False
        except Exception as e:
            self.logger.error(f"Error creating hotspot connection: {e}")
            return False
    
    def _activate_connection(self) -> bool:
        """Activate the hotspot connection"""
        try:
            cmd = ["nmcli", "connection", "up", self.connection_name]
            
            self.logger.debug("Activating hotspot connection")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.logger.info("Hotspot connection activated")
                return True
            else:
                self.logger.error(f"Failed to activate hotspot: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout activating hotspot connection")
            return False
        except Exception as e:
            self.logger.error(f"Error activating hotspot connection: {e}")
            return False
    
    def _deactivate_connection(self):
        """Deactivate the hotspot connection"""
        try:
            cmd = ["nmcli", "connection", "down", self.connection_name]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                self.logger.debug("Hotspot connection deactivated")
            else:
                self.logger.debug(f"Could not deactivate connection: {result.stderr}")
                
        except Exception as e:
            self.logger.debug(f"Error deactivating connection: {e}")
    
    def _verify_hotspot(self) -> bool:
        """Verify that the hotspot is working"""
        try:
            # Check if interface has the expected IP
            cmd = ["ip", "addr", "show", self.interface]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and self.ip_address in result.stdout:
                self.logger.debug("Hotspot IP address verified")
                
                # Check if connection is active
                cmd = ["nmcli", "connection", "show", "--active"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and self.connection_name in result.stdout:
                    self.logger.debug("Hotspot connection is active")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error verifying hotspot: {e}")
            return False
    
    def get_connection_info(self) -> Dict[str, Any]:
        """Get information about the current hotspot connection"""
        info = {
            'connection_name': self.connection_name,
            'ssid': self.ssid,
            'interface': self.interface,
            'ip_address': self.ip_address,
            'active': False,
            'connected_clients': 0
        }
        
        try:
            # Check if connection is active
            cmd = ["nmcli", "connection", "show", "--active"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and self.connection_name in result.stdout:
                info['active'] = True
                
                # Try to get connected clients count (this is harder with NetworkManager)
                # For now, we'll leave it as 0 since getting DHCP leases requires more work
                
        except Exception as e:
            self.logger.debug(f"Error getting connection info: {e}")
        
        return info
    
    def is_active(self) -> bool:
        """Check if the hotspot is currently active"""
        try:
            cmd = ["nmcli", "connection", "show", "--active"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0 and self.connection_name in result.stdout
        except:
            return False
    
    def restart_hotspot(self) -> bool:
        """Restart the hotspot connection"""
        self.logger.info("Restarting WiFi hotspot...")
        
        if self.is_active():
            self._deactivate_connection()
            time.sleep(2)
        
        return self._activate_connection() and self._verify_hotspot()
    
    def show_security_settings(self):
        """Display current WiFi security settings for debugging"""
        try:
            cmd = ["nmcli", "connection", "show", self.connection_name]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                security_lines = [line for line in lines if 'wifi-sec' in line]
                
                self.logger.info("Current WiFi Security Settings:")
                for line in security_lines:
                    if line.strip():
                        self.logger.info(f"  {line.strip()}")
            else:
                self.logger.warning("Could not retrieve security settings")
                
        except Exception as e:
            self.logger.error(f"Error retrieving security settings: {e}")
    
    def show_dhcp_status(self):
        """Display DHCP server status for debugging"""
        try:
            self.logger.info("DHCP Server Status:")
            self.logger.info(f"  DHCP Running: {self.dhcp_server.is_running()}")
            self.logger.info(f"  DHCP Range: {self.dhcp_server.dhcp_start} - {self.dhcp_server.dhcp_end}")
            self.logger.info(f"  Server IP: {self.dhcp_server.server_ip}")
            self.logger.info(f"  Interface: {self.dhcp_server.interface}")
            
            # Show current leases if available
            leases = self.dhcp_server.get_dhcp_leases()
            if leases:
                self.logger.info(f"  Active Leases: {len(leases)}")
                for lease in leases:
                    self.logger.info(f"    {lease}")
            else:
                self.logger.info("  Active Leases: None or unable to read")
                
        except Exception as e:
            self.logger.error(f"Error retrieving DHCP status: {e}")
    
    def get_network_status(self) -> dict:
        """Get comprehensive network status"""
        status = {
            "wifi_active": self.is_active(),
            "dhcp_running": self.dhcp_server.is_running() if hasattr(self, 'dhcp_server') else False,
            "connection_name": self.connection_name,
            "ssid": self.ssid,
            "ip_address": self.ip_address,
            "interface": self.interface
        }
        
        if hasattr(self, 'dhcp_server'):
            status.update({
                "dhcp_range": f"{self.dhcp_server.dhcp_start} - {self.dhcp_server.dhcp_end}",
                "dhcp_server_ip": self.dhcp_server.server_ip
            })
        
        return status