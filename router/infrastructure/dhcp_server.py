"""
DHCP Server Manager
Handles DHCP server setup and management for the WiFi access point
"""

import subprocess
import time
import os
import ipaddress
from typing import Dict, List, Optional
from pathlib import Path

from core.config import RouterConfig
from core.logger import get_logger


class DHCPServerManager:
    """
    Manages DHCP server using dnsmasq for the WiFi access point
    """
    
    def __init__(self, config: RouterConfig):
        self.config = config
        self.logger = get_logger(__name__)
        
        # DHCP settings - will be updated when interface is detected
        self.interface = None  # Will be detected dynamically
        self.server_ip = config.wifi.server_host
        self.network = ipaddress.IPv4Network(f"{self.server_ip}/24", strict=False)
        
        # DHCP range (e.g., 192.168.50.10 to 192.168.50.100)
        self.dhcp_start = str(self.network.network_address + 10)
        self.dhcp_end = str(self.network.network_address + 100)
        
        # Configuration files
        self.config_dir = Path("/etc/dnsmasq.d")
        self.config_file = self.config_dir / f"iot-router-{config.router_id}.conf"
        self.pid_file = f"/var/run/dnsmasq-iot-{config.router_id}.pid"
        
        self.logger.info("DHCP Server Manager initialized",
                        server_ip=self.server_ip,
                        dhcp_range=f"{self.dhcp_start}-{self.dhcp_end}")
    
    def _detect_wifi_interface(self) -> Optional[str]:
        """
        Detect the active WiFi interface with our server IP
        Returns interface name or None if not found
        """
        try:
            # Get all network interfaces with IP addresses
            result = subprocess.run(["ip", "addr", "show"], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                self.logger.error("Failed to get network interfaces")
                return None
            
            # Look for interface with our server IP
            current_interface = None
            for line in result.stdout.split('\n'):
                # Check for interface line (e.g., "2: wlp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP>")
                if ': ' in line and '<' in line and 'UP' in line:
                    parts = line.split(': ')
                    if len(parts) >= 2:
                        current_interface = parts[1].split(':')[0].strip()
                
                # Check for our IP address on current interface
                elif current_interface and f"inet {self.server_ip}/" in line:
                    self.logger.info(f"Detected WiFi interface: {current_interface}")
                    return current_interface
            
            self.logger.error(f"No interface found with IP {self.server_ip}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error detecting WiFi interface: {e}")
            return None
    
    def setup_dhcp_server(self) -> bool:
        """
        Setup DHCP server using dnsmasq
        Returns True if successful
        """
        try:
            self.logger.info("Setting up DHCP server...")
            
            # Check if we're running as root
            if os.geteuid() != 0:
                self.logger.error("Root privileges required for DHCP server setup")
                return False
            
            # Stop any existing dnsmasq processes first
            self.logger.debug("Stopping any existing dnsmasq processes...")
            self._stop_all_dnsmasq_processes()
            
            # Detect the WiFi interface
            self.interface = self._detect_wifi_interface()
            if not self.interface:
                self.logger.warning("Could not detect WiFi interface, using fallback mode")
            else:
                self.logger.info(f"Using WiFi interface: {self.interface}")
            
            # Install dnsmasq if not present
            if not self._check_dnsmasq_installed():
                if not self._install_dnsmasq():
                    return False
            
            # Stop any existing dnsmasq instance for our router
            self._stop_dhcp_server()
            
            # Create configuration
            if not self._create_dhcp_config():
                return False
            
            # Start DHCP server
            if not self._start_dhcp_server():
                return False
            
            # Verify DHCP server is running
            if self._verify_dhcp_server():
                self.logger.info("DHCP server setup successful",
                               dhcp_range=f"{self.dhcp_start}-{self.dhcp_end}",
                               lease_time="12h")
                return True
            else:
                self.logger.error("DHCP server verification failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Error setting up DHCP server: {e}", exc_info=True)
            return False
    
    def teardown_dhcp_server(self) -> bool:
        """
        Teardown DHCP server
        Returns True if successful
        """
        try:
            self.logger.info("Tearing down DHCP server...")
            
            # Stop DHCP server
            self._stop_dhcp_server()
            
            # Remove configuration file
            if self.config_file.exists():
                self.config_file.unlink()
                self.logger.debug(f"Removed config file: {self.config_file}")
            
            self.logger.info("DHCP server torn down successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error tearing down DHCP server: {e}")
            return False
    
    def _check_dnsmasq_installed(self) -> bool:
        """Check if dnsmasq is installed"""
        try:
            result = subprocess.run(["which", "dnsmasq"], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def _install_dnsmasq(self) -> bool:
        """Install dnsmasq package"""
        try:
            self.logger.info("Installing dnsmasq...")
            
            # Update package list
            subprocess.run(["apt", "update"], check=True, timeout=60)
            
            # Install dnsmasq
            subprocess.run(["apt", "install", "-y", "dnsmasq"], 
                         check=True, timeout=120)
            
            self.logger.info("dnsmasq installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install dnsmasq: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error installing dnsmasq: {e}")
            return False
    
    def _create_dhcp_config(self) -> bool:
        """Create dnsmasq configuration for DHCP"""
        try:
            # Ensure config directory exists
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            # Create config with or without specific interface binding
            if self.interface:
                interface_config = f"interface={self.interface}\n"
                bind_config = "bind-interfaces"
            else:
                # Fallback: listen on all interfaces but restrict by IP range
                interface_config = "# Listen on all interfaces (fallback mode)\n"
                bind_config = "bind-dynamic"
            
            config_content = f"""# IoT Router DHCP Configuration - {self.config.router_id}
# Generated automatically - do not edit manually

{interface_config}
# DHCP range and lease time
dhcp-range={self.dhcp_start},{self.dhcp_end},12h

# Router/gateway IP
dhcp-option=3,{self.server_ip}

# DNS server (use router as DNS)
dhcp-option=6,{self.server_ip}

# Domain name
domain=iot.local

# Log DHCP transactions
log-dhcp

# Don't read /etc/resolv.conf
no-resolv

# Don't read /etc/hosts
no-hosts

# Authoritative DHCP server for this network
dhcp-authoritative

# PID file
pid-file={self.pid_file}

# Binding configuration
{bind_config}

# Don't provide DNS service on other interfaces
except-interface=lo
"""
            
            with open(self.config_file, 'w') as f:
                f.write(config_content)
            
            # Set proper permissions
            os.chmod(self.config_file, 0o644)
            
            self.logger.debug(f"Created DHCP config: {self.config_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating DHCP config: {e}")
            return False
    
    def _start_dhcp_server(self) -> bool:
        """Start dnsmasq DHCP server with proper process management"""
        try:
            # First check if port 67 (DHCP) is already in use
            port_check = subprocess.run(["netstat", "-ln"], capture_output=True, text=True)
            if ":67 " in port_check.stdout:
                self.logger.warning("Port 67 (DHCP) appears to be in use")
                # Try to find what's using it
                port_user = subprocess.run(["lsof", "-i", ":67"], capture_output=True, text=True)
                if port_user.returncode == 0:
                    self.logger.warning(f"Port 67 is used by: {port_user.stdout}")
            
            # Test configuration first
            test_cmd = ["dnsmasq", "--test", f"--conf-file={self.config_file}"]
            test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=5)
            
            if test_result.returncode != 0:
                self.logger.error(f"dnsmasq configuration test failed: {test_result.stderr}")
                return False
            else:
                self.logger.debug("dnsmasq configuration test passed")
            
            # Start dnsmasq in daemon mode (simple approach)
            cmd = ["dnsmasq", f"--conf-file={self.config_file}"]
            
            self.logger.debug(f"Starting dnsmasq daemon with command: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.logger.info("DHCP server daemon started successfully")
                # Wait a moment for it to start up
                time.sleep(2)
                return True
            else:
                self.logger.error(f"dnsmasq failed to start:")
                self.logger.error(f"  Return code: {result.returncode}")
                self.logger.error(f"  Stdout: {result.stdout}")
                self.logger.error(f"  Stderr: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout starting dnsmasq daemon")
            return False
        except Exception as e:
            self.logger.error(f"Error starting DHCP server: {e}")
            return False
    
    def _stop_dhcp_server(self):
        """Stop existing dnsmasq instance for our router"""
        try:
            stopped_any = False
            
            # Kill by PID file if it exists
            if os.path.exists(self.pid_file):
                with open(self.pid_file, 'r') as f:
                    pid = int(f.read().strip())
                try:
                    os.kill(pid, 15)  # SIGTERM
                    time.sleep(1)
                    # Check if still running
                    try:
                        os.kill(pid, 0)  # Check if process exists
                        os.kill(pid, 9)   # SIGKILL if still running
                        self.logger.debug("Had to force-kill dnsmasq process")
                    except ProcessLookupError:
                        pass  # Process terminated gracefully
                    stopped_any = True
                except ProcessLookupError:
                    pass  # Process already dead
                
                # Remove PID file
                os.unlink(self.pid_file)
                self.logger.debug("Removed PID file")
            
            # Also try killing by process name and config file (backup method)
            try:
                result = subprocess.run(["pkill", "-f", f"dnsmasq.*{self.config.router_id}"], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    stopped_any = True
                    self.logger.debug("Stopped dnsmasq by process name")
            except Exception:
                pass
            
            # Extra cleanup: kill any dnsmasq using our config file
            try:
                result = subprocess.run(["pkill", "-f", f"dnsmasq.*{self.config_file}"], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    stopped_any = True
                    self.logger.debug("Stopped dnsmasq by config file")
            except Exception:
                pass
            
            if stopped_any:
                self.logger.debug("Stopped DHCP server processes")
            
        except Exception as e:
            self.logger.debug(f"Error stopping DHCP server: {e}")
    
    def _stop_all_dnsmasq_processes(self):
        """Stop ALL dnsmasq processes to avoid conflicts"""
        try:
            stopped_any = False
            
            # Kill all dnsmasq processes
            result = subprocess.run(["pkill", "-f", "dnsmasq"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                stopped_any = True
                self.logger.debug("Stopped all dnsmasq processes")
            
            # Also try killing by exact process name
            result = subprocess.run(["killall", "dnsmasq"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                stopped_any = True
                self.logger.debug("Killed all dnsmasq processes")
            
            # Wait a moment for processes to actually stop
            if stopped_any:
                time.sleep(2)
                self.logger.debug("Waited for dnsmasq processes to stop")
            
            # Clean up any stale PID files in common locations
            pid_locations = [
                "/var/run/dnsmasq.pid",
                "/var/run/dnsmasq/dnsmasq.pid",
                "/run/dnsmasq.pid"
            ]
            
            for pid_location in pid_locations:
                if os.path.exists(pid_location):
                    try:
                        os.unlink(pid_location)
                        self.logger.debug(f"Removed stale PID file: {pid_location}")
                    except Exception:
                        pass
            
        except Exception as e:
            self.logger.debug(f"Error stopping all dnsmasq processes: {e}")
    
    def _verify_dhcp_server(self) -> bool:
        """Verify DHCP server is running correctly"""
        try:
            # Check if PID file exists and process is running
            if os.path.exists(self.pid_file):
                with open(self.pid_file, 'r') as f:
                    pid = int(f.read().strip())
                
                # Check if process exists
                try:
                    os.kill(pid, 0)  # Signal 0 just checks if process exists
                    self.logger.debug("DHCP server process verified")
                    return True
                except ProcessLookupError:
                    self.logger.warning("DHCP server PID file exists but process not found")
                    return False
            else:
                self.logger.warning("DHCP server PID file not found")
                return False
                
        except Exception as e:
            self.logger.error(f"Error verifying DHCP server: {e}")
            return False
    
    def get_dhcp_leases(self) -> List[Dict[str, str]]:
        """Get current DHCP leases"""
        leases = []
        lease_file = "/var/lib/dhcp/dhcpd.leases"
        
        # dnsmasq uses a different lease file location
        dnsmasq_lease_file = "/var/lib/dhcp/dhcpcd.leases"
        
        try:
            # Try to parse lease file (this is a simplified version)
            # In a real implementation, you'd want to parse the actual lease format
            self.logger.debug("DHCP lease parsing not fully implemented yet")
            
        except Exception as e:
            self.logger.debug(f"Error reading DHCP leases: {e}")
            
        return leases
    
    def is_running(self) -> bool:
        """Check if DHCP server is currently running"""
        return self._verify_dhcp_server()