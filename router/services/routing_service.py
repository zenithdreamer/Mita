"""
Routing Service
Manages routing table and message forwarding between devices
"""

import threading
import time
from typing import Dict, Optional, Set
from enum import Enum
from dataclasses import dataclass

from core.config import RoutingConfig
from core.logger import get_logger
from protocol import PacketCrypto


class InterfaceType(Enum):
    """Types of network interfaces"""
    WIFI = "wifi"
    BLE = "ble"
    ZIGBEE = "zigbee"  # Future expansion
    LORA = "lora"      # Future expansion


@dataclass
class RouteEntry:
    """Routing table entry for a device"""
    node_addr: int
    device_id: str
    interface_type: InterfaceType
    connection_handle: any  # Socket for WiFi, BLE handle for BLE, etc.
    session_crypto: PacketCrypto
    last_seen: float
    connection_info: Dict[str, any]


class RoutingService:
    """
    Service for managing device routing and forwarding
    """
    
    # Address space constants
    ROUTER_ADDRESS = 0x0000
    BROADCAST_ADDRESS = 0xFFFF
    MIN_CLIENT_ADDRESS = 0x0001
    MAX_CLIENT_ADDRESS = 0xFFFE
    
    def __init__(self, config: RoutingConfig):
        self.config = config
        self.logger = get_logger(__name__)
        
        # Routing table
        self.routes: Dict[int, RouteEntry] = {}
        self.device_id_to_addr: Dict[str, int] = {}
        self.next_address = self.MIN_CLIENT_ADDRESS
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Service state
        self.running = False
        
        self.logger.info("Routing service initialized", max_devices=config.max_devices)
    
    def start(self):
        """Start the routing service"""
        with self.lock:
            if self.running:
                return
            
            self.running = True
            self.logger.info("Routing service started")
    
    def stop(self):
        """Stop the routing service"""
        with self.lock:
            if not self.running:
                return
            
            self.running = False
            
            # Clear all routes
            self.routes.clear()
            self.device_id_to_addr.clear()
            
            self.logger.info("Routing service stopped")
    
    def allocate_address(self, device_id: str) -> int:
        """
        Allocate a unique address for a device
        Returns existing address if device already has one
        """
        with self.lock:
            # Check if device already has an address
            if device_id in self.device_id_to_addr:
                existing_addr = self.device_id_to_addr[device_id]
                self.logger.debug(f"Device {device_id} already has address 0x{existing_addr:04X}")
                return existing_addr
            
            # Check device limit
            if len(self.routes) >= self.config.max_devices:
                raise RuntimeError(f"Maximum device limit reached: {self.config.max_devices}")
            
            # Find next available address
            original_next = self.next_address
            while self.next_address in self.routes:
                self.next_address += 1
                if self.next_address > self.MAX_CLIENT_ADDRESS:
                    self.next_address = self.MIN_CLIENT_ADDRESS
                
                # Check if we've wrapped around completely
                if self.next_address == original_next:
                    raise RuntimeError("No available addresses in range")
            
            addr = self.next_address
            self.device_id_to_addr[device_id] = addr
            self.next_address += 1
            
            self.logger.debug(f"Allocated address 0x{addr:04X} for device {device_id}")
            return addr
    
    def add_route(self, device_id: str, interface_type: InterfaceType,
                  connection_handle: any, session_crypto: PacketCrypto,
                  connection_info: Dict[str, any] = None) -> int:
        """
        Add a new route entry
        Returns the assigned address
        """
        with self.lock:
            if not self.running:
                raise RuntimeError("Routing service is not running")
            
            addr = self.allocate_address(device_id)
            
            route = RouteEntry(
                node_addr=addr,
                device_id=device_id,
                interface_type=interface_type,
                connection_handle=connection_handle,
                session_crypto=session_crypto,
                last_seen=time.time(),
                connection_info=connection_info or {}
            )
            
            self.routes[addr] = route
            
            self.logger.info(f"Added route for device {device_id}",
                           address=f"0x{addr:04X}",
                           interface=interface_type.value)
            
            return addr
    
    def remove_route(self, addr: int) -> bool:
        """Remove a route entry by address"""
        with self.lock:
            if addr not in self.routes:
                return False
            
            route = self.routes[addr]
            device_id = route.device_id
            
            del self.routes[addr]
            
            if device_id in self.device_id_to_addr:
                del self.device_id_to_addr[device_id]
            
            self.logger.info(f"Removed route for device {device_id}",
                           address=f"0x{addr:04X}")
            
            return True
    
    def remove_route_by_device_id(self, device_id: str) -> bool:
        """Remove a route entry by device ID"""
        with self.lock:
            if device_id not in self.device_id_to_addr:
                return False
            
            addr = self.device_id_to_addr[device_id]
            return self.remove_route(addr)
    
    def get_route(self, addr: int) -> Optional[RouteEntry]:
        """Get route entry by address"""
        with self.lock:
            return self.routes.get(addr)
    
    def get_route_by_device_id(self, device_id: str) -> Optional[RouteEntry]:
        """Get route entry by device ID"""
        with self.lock:
            if device_id not in self.device_id_to_addr:
                return None
            
            addr = self.device_id_to_addr[device_id]
            return self.routes.get(addr)
    
    def update_last_seen(self, addr: int):
        """Update last seen timestamp for a route"""
        with self.lock:
            if addr in self.routes:
                self.routes[addr].last_seen = time.time()
    
    def get_all_routes(self) -> Dict[int, RouteEntry]:
        """Get all route entries (copy)"""
        with self.lock:
            return self.routes.copy()
    
    def get_routes_by_interface(self, interface_type: InterfaceType) -> Dict[int, RouteEntry]:
        """Get all routes for a specific interface type"""
        with self.lock:
            return {
                addr: route for addr, route in self.routes.items()
                if route.interface_type == interface_type
            }
    
    def cleanup_stale_routes(self, timeout_seconds: int) -> int:
        """
        Remove routes that haven't been seen for timeout_seconds
        Returns number of routes removed
        """
        with self.lock:
            current_time = time.time()
            stale_addresses = []
            
            for addr, route in self.routes.items():
                if current_time - route.last_seen > timeout_seconds:
                    stale_addresses.append(addr)
            
            removed_count = 0
            for addr in stale_addresses:
                if self.remove_route(addr):
                    removed_count += 1
            
            if removed_count > 0:
                self.logger.info(f"Cleaned up {removed_count} stale routes")
            
            return removed_count
    
    def get_device_count(self) -> int:
        """Get total number of connected devices"""
        with self.lock:
            return len(self.routes)
    
    def get_device_count_by_interface(self, interface_type: InterfaceType) -> int:
        """Get number of devices connected via specific interface"""
        with self.lock:
            return sum(1 for route in self.routes.values()
                      if route.interface_type == interface_type)
    
    def is_address_available(self, addr: int) -> bool:
        """Check if an address is available for allocation"""
        with self.lock:
            return (self.MIN_CLIENT_ADDRESS <= addr <= self.MAX_CLIENT_ADDRESS and
                    addr not in self.routes)
    
    def get_address_for_device(self, device_id: str) -> Optional[int]:
        """Get the address assigned to a device, if any"""
        with self.lock:
            return self.device_id_to_addr.get(device_id)