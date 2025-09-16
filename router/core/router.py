"""
Core IoT Router implementation
Main router class that orchestrates all components
"""

import threading
import time
import asyncio
from typing import Dict, Optional, Any

from core.config import RouterConfig
from core.logger import get_logger
from core.transport_interface import TransportInterface
from services.routing_service import RoutingService
from services.statistics_service import StatisticsService
from services.device_management_service import DeviceManagementService
from infrastructure.wifi_manager import WiFiAccessPointManager


class IoTRouter:
    """
    Main IoT Router class
    Orchestrates all router components and services
    """
    
    def __init__(self, config: RouterConfig):
        self.config = config
        self.logger = get_logger(__name__)
        
        # Validate configuration
        if not self.config.validate():
            raise ValueError("Invalid configuration")
        
        # Core services
        self.routing_service = RoutingService(config.routing)
        self.statistics_service = StatisticsService()
        self.device_management = DeviceManagementService(
            self.routing_service, 
            self.statistics_service
        )
        
        # Transport layers
        self.transports: Dict[str, TransportInterface] = {}
        self.wifi_ap_manager: Optional[WiFiAccessPointManager] = None
        
        # Control state
        self.running = False
        self.main_loop_thread: Optional[threading.Thread] = None
        self.status_thread: Optional[threading.Thread] = None
        
        self.logger.info("IoT Router initialized", 
                        router_id=self.config.router_id,
                        wifi_enabled=self.config.wifi.enabled,
                        ble_enabled=self.config.ble.enabled)
    
    def start(self) -> bool:
        """
        Start the IoT router and all enabled transports
        Returns True if started successfully
        """
        try:
            self.logger.info("Starting IoT Router...")
            
            # Initialize WiFi transport
            if self.config.wifi.enabled:
                if not self._setup_wifi_transport():
                    self.logger.warning("WiFi transport failed to initialize")
                    if not self.config.ble.enabled:
                        self.logger.error("No transports available, cannot start router")
                        return False
            
            # Initialize BLE transport
            if self.config.ble.enabled:
                if not self._setup_ble_transport():
                    self.logger.warning("BLE transport failed to initialize")
                    if not self.config.wifi.enabled or 'wifi' not in self.transports:
                        self.logger.error("No transports available, cannot start router")
                        return False
            
            # Start services
            self.routing_service.start()
            self.device_management.start()
            
            # Start monitoring
            self.running = True
            self._start_background_tasks()
            
            # Start main loop
            self._run_main_loop()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start router: {e}", exc_info=True)
            self.stop()
            return False
    
    def stop(self):
        """Stop the IoT router and all services"""
        self.logger.info("Stopping IoT Router...")
        
        # Stop main loop
        self.running = False
        
        # Wait for threads to finish
        if self.main_loop_thread and self.main_loop_thread.is_alive():
            self.main_loop_thread.join(timeout=5)
        
        if self.status_thread and self.status_thread.is_alive():
            self.status_thread.join(timeout=5)
        
        # Stop all transports
        for name, transport in self.transports.items():
            try:
                self.logger.debug(f"Stopping {name} transport")
                transport.stop()
            except Exception as e:
                self.logger.error(f"Error stopping {name} transport: {e}")
        
        # Stop WiFi AP
        if self.wifi_ap_manager:
            try:
                self.wifi_ap_manager.teardown_hotspot()
            except Exception as e:
                self.logger.error(f"Error stopping WiFi AP: {e}")
        
        # Stop services
        self.device_management.stop()
        self.routing_service.stop()
        
        self.logger.info("IoT Router stopped")
    
    def _setup_wifi_transport(self) -> bool:
        """Setup WiFi access point and transport"""
        try:
            from transports.wifi_transport import WiFiTransport
            
            self.logger.info("Setting up WiFi transport...")
            
            # Setup WiFi Access Point
            if not self.config.development.skip_ap_setup:
                self.wifi_ap_manager = WiFiAccessPointManager(self.config)
                if not self.wifi_ap_manager.setup_hotspot():
                    self.logger.error("Failed to setup WiFi Access Point")
                    return False
                
                # Display security settings for debugging
                self.wifi_ap_manager.show_security_settings()
                
                # Wait for interface to be ready
                time.sleep(3)
            
            # Initialize WiFi transport
            wifi_transport = WiFiTransport(
                config=self.config,
                routing_service=self.routing_service,
                device_management=self.device_management,
                statistics_service=self.statistics_service
            )
            
            if wifi_transport.start():
                self.transports['wifi'] = wifi_transport
                self.logger.info("WiFi transport started successfully")
                return True
            else:
                self.logger.error("Failed to start WiFi transport")
                return False
                
        except Exception as e:
            self.logger.error(f"Error setting up WiFi transport: {e}", exc_info=True)
            return False
    
    def _setup_ble_transport(self) -> bool:
        """Setup BLE transport"""
        try:
            from transports.ble_transport import BLETransport
            
            self.logger.info("Setting up BLE transport...")
            
            ble_transport = BLETransport(
                config=self.config,
                routing_service=self.routing_service,
                device_management=self.device_management,
                statistics_service=self.statistics_service
            )
            
            if ble_transport.start():
                self.transports['ble'] = ble_transport
                self.logger.info("BLE transport started successfully")
                return True
            else:
                self.logger.error("Failed to start BLE transport")
                return False
                
        except Exception as e:
            self.logger.error(f"Error setting up BLE transport: {e}", exc_info=True)
            return False
    
    def _start_background_tasks(self):
        """Start background monitoring tasks"""
        # Status monitoring thread
        if self.config.logging.status_interval > 0:
            self.status_thread = threading.Thread(
                target=self._status_monitor_loop, 
                daemon=True, 
                name="StatusMonitor"
            )
            self.status_thread.start()
            self.logger.debug("Status monitoring thread started")
    
    def _run_main_loop(self):
        """Run the main router loop"""
        self.logger.info("Router main loop started")
        
        try:
            while self.running:
                # Perform periodic maintenance
                self._periodic_maintenance()
                
                # Sleep for cleanup interval
                time.sleep(self.config.routing.cleanup_interval)
                
        except KeyboardInterrupt:
            self.logger.info("Received keyboard interrupt")
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}", exc_info=True)
        finally:
            self.stop()
    
    def _periodic_maintenance(self):
        """Perform periodic maintenance tasks"""
        try:
            # Clean up stale routes
            removed_routes = self.routing_service.cleanup_stale_routes(
                timeout_seconds=self.config.routing.device_timeout
            )
            
            if removed_routes > 0:
                self.logger.info(f"Cleaned up {removed_routes} stale routes")
            
            # Update statistics
            self.statistics_service.update_periodic_stats()
            
        except Exception as e:
            self.logger.error(f"Error in periodic maintenance: {e}", exc_info=True)
    
    def _status_monitor_loop(self):
        """Status monitoring loop running in background thread"""
        self.logger.debug("Status monitor started")
        
        while self.running:
            try:
                self._log_status()
                time.sleep(self.config.logging.status_interval)
            except Exception as e:
                self.logger.error(f"Error in status monitor: {e}")
                time.sleep(10)  # Wait before retrying
    
    def _log_status(self):
        """Log current router status"""
        try:
            # Get statistics
            stats = self.statistics_service.get_stats()
            routes = self.routing_service.get_all_routes()
            
            # Log summary
            self.logger.info(
                "Router Status",
                devices=len(routes),
                packets_routed=stats.packets_routed,
                packets_dropped=stats.packets_dropped,
                bytes_transferred=stats.bytes_transferred,
                handshakes=stats.handshakes_completed,
                errors=stats.errors
            )
            
            # Log device details in debug mode
            if self.logger.logger.isEnabledFor(10):  # DEBUG level
                for addr, route in routes.items():
                    last_seen = time.time() - route.last_seen
                    self.logger.debug(
                        "Connected device",
                        device_id=route.device_id,
                        address=f"0x{addr:04X}",
                        interface=route.interface_type.value,
                        last_seen_seconds=f"{last_seen:.1f}"
                    )
            
            # Log transport status
            for name, transport in self.transports.items():
                devices = transport.get_connected_devices()
                self.logger.debug(f"{name.upper()} transport", connected_devices=len(devices))
                
        except Exception as e:
            self.logger.error(f"Error logging status: {e}")
    
    # Public API methods for external control
    
    def send_message(self, device_id: str, message: bytes) -> bool:
        """Send a message to a specific device"""
        try:
            return self.device_management.send_message_to_device(device_id, message)
        except Exception as e:
            self.logger.error(f"Error sending message to {device_id}: {e}")
            return False
    
    def broadcast_message(self, message: bytes) -> int:
        """Broadcast a message to all connected devices"""
        try:
            return self.device_management.broadcast_message(message)
        except Exception as e:
            self.logger.error(f"Error broadcasting message: {e}")
            return 0
    
    def get_connected_devices(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all connected devices"""
        try:
            return self.device_management.get_device_list()
        except Exception as e:
            self.logger.error(f"Error getting device list: {e}")
            return {}
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get router statistics"""
        return self.statistics_service.get_stats().to_dict()
    
    def get_router_info(self) -> Dict[str, Any]:
        """Get general router information"""
        return {
            'router_id': self.config.router_id,
            'running': self.running,
            'transports': list(self.transports.keys()),
            'connected_devices': len(self.routing_service.get_all_routes()),
            'uptime_seconds': self.statistics_service.get_uptime()
        }