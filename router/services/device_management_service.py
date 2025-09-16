"""
Device Management Service
Handles device lifecycle, messaging, and coordination between transports
"""

import threading
import time
from typing import Dict, Any, Optional, List

from core.logger import get_logger
from services.routing_service import RoutingService
from services.statistics_service import StatisticsService
from protocol import ProtocolPacket, MessageType


class DeviceManagementService:
    """
    Service for managing device connections, messaging, and lifecycle
    """
    
    def __init__(self, routing_service: RoutingService, statistics_service: StatisticsService):
        self.routing_service = routing_service
        self.statistics_service = statistics_service
        self.logger = get_logger(__name__)
        
        # Message handlers for different transport types
        self.message_handlers: Dict[str, callable] = {}
        
        # Device connection tracking
        self.device_connections: Dict[str, Dict[str, Any]] = {}
        self.connection_lock = threading.Lock()
        
        # Service state
        self.running = False
        
        self.logger.info("Device management service initialized")
    
    def start(self):
        """Start the device management service"""
        if self.running:
            return
        
        self.running = True
        self.logger.info("Device management service started")
    
    def stop(self):
        """Stop the device management service"""
        if not self.running:
            return
        
        self.running = False
        
        # Clear device connections
        with self.connection_lock:
            self.device_connections.clear()
        
        self.logger.info("Device management service stopped")
    
    def register_message_handler(self, interface_type: str, handler: callable):
        """Register a message handler for an interface type"""
        self.message_handlers[interface_type] = handler
        self.logger.debug(f"Registered message handler for {interface_type}")
    
    def handle_device_connected(self, device_id: str, interface_type: str, 
                              connection_info: Dict[str, Any]):
        """Handle a new device connection"""
        with self.connection_lock:
            self.device_connections[device_id] = {
                'interface_type': interface_type,
                'connected_at': time.time(),
                'connection_info': connection_info
            }
        
        self.logger.info(f"Device connected: {device_id}",
                        interface=interface_type)
    
    def handle_device_disconnected(self, device_id: str):
        """Handle device disconnection"""
        with self.connection_lock:
            connection_info = self.device_connections.pop(device_id, None)
        
        # Remove from routing table
        self.routing_service.remove_route_by_device_id(device_id)
        
        # Remove device statistics
        self.statistics_service.remove_device_stats(device_id)
        
        if connection_info:
            interface_type = connection_info['interface_type']
            connected_duration = time.time() - connection_info['connected_at']
            
            self.logger.info(f"Device disconnected: {device_id}",
                           interface=interface_type,
                           duration_seconds=f"{connected_duration:.1f}")
        else:
            self.logger.info(f"Device disconnected: {device_id}")
    
    def handle_handshake_completed(self, device_id: str, assigned_address: int,
                                 interface_type: str):
        """Handle successful handshake completion"""
        self.statistics_service.increment_handshakes_completed(interface_type)
        
        # Update device connection info
        with self.connection_lock:
            if device_id in self.device_connections:
                self.device_connections[device_id]['assigned_address'] = assigned_address
                self.device_connections[device_id]['authenticated_at'] = time.time()
        
        self.logger.info(f"Handshake completed for device {device_id}",
                        address=f"0x{assigned_address:04X}",
                        interface=interface_type)
    
    def handle_handshake_failed(self, device_id: str, interface_type: str, reason: str):
        """Handle failed handshake"""
        self.statistics_service.increment_handshakes_failed(interface_type)
        
        self.logger.warning(f"Handshake failed for device {device_id}",
                          interface=interface_type,
                          reason=reason)
    
    def send_message_to_device(self, device_id: str, message: bytes) -> bool:
        """
        Send a message to a specific device
        Returns True if message was sent successfully
        """
        try:
            # Get route for device
            route = self.routing_service.get_route_by_device_id(device_id)
            if not route:
                self.logger.warning(f"No route found for device {device_id}")
                return False
            
            # Get message handler for interface
            interface_type = route.interface_type.value
            if interface_type not in self.message_handlers:
                self.logger.error(f"No message handler for interface {interface_type}")
                return False
            
            # Create packet
            packet = ProtocolPacket(
                MessageType.DATA,
                source_addr=RoutingService.ROUTER_ADDRESS,
                dest_addr=route.node_addr,
                payload=message,
                encrypted=True
            )
            
            # Send via handler
            handler = self.message_handlers[interface_type]
            success = handler(device_id, packet)
            
            if success:
                # Update statistics
                self.statistics_service.increment_packets_routed(
                    bytes_count=len(message),
                    interface=interface_type
                )
                
                self.statistics_service.update_device_stats(
                    device_id=device_id,
                    packets_sent=1,
                    bytes_transferred=len(message)
                )
                
                # Update last seen
                self.routing_service.update_last_seen(route.node_addr)
                
                self.logger.debug(f"Message sent to device {device_id}",
                                bytes=len(message))
            else:
                self.statistics_service.increment_packets_dropped(interface_type)
                self.logger.warning(f"Failed to send message to device {device_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error sending message to device {device_id}: {e}")
            self.statistics_service.increment_errors()
            return False
    
    def broadcast_message(self, message: bytes) -> int:
        """
        Broadcast a message to all connected devices
        Returns number of devices that received the message
        """
        success_count = 0
        routes = self.routing_service.get_all_routes()
        
        if not routes:
            self.logger.debug("No devices to broadcast to")
            return 0
        
        self.logger.info(f"Broadcasting message to {len(routes)} devices",
                        bytes=len(message))
        
        for addr, route in routes.items():
            try:
                device_id = route.device_id
                if self.send_message_to_device(device_id, message):
                    success_count += 1
                else:
                    self.logger.warning(f"Failed to broadcast to device {device_id}")
                    
            except Exception as e:
                self.logger.error(f"Error broadcasting to device {route.device_id}: {e}")
        
        self.logger.info(f"Broadcast completed",
                        successful=success_count,
                        total=len(routes))
        
        return success_count
    
    def handle_incoming_message(self, device_id: str, packet: ProtocolPacket,
                              interface_type: str):
        """Handle incoming message from a device"""
        try:
            # Update statistics
            self.statistics_service.increment_packets_routed(
                bytes_count=len(packet.payload),
                interface=interface_type
            )
            
            self.statistics_service.update_device_stats(
                device_id=device_id,
                packets_received=1,
                bytes_transferred=len(packet.payload)
            )
            
            # Update last seen
            route = self.routing_service.get_route_by_device_id(device_id)
            if route:
                self.routing_service.update_last_seen(route.node_addr)
            
            # Handle different message types
            if packet.msg_type == MessageType.DATA:
                self._handle_data_message(device_id, packet, interface_type)
            else:
                self.logger.debug(f"Received {packet.msg_type.name} from device {device_id}")
            
        except Exception as e:
            self.logger.error(f"Error handling message from device {device_id}: {e}")
            self.statistics_service.increment_errors(interface_type)
    
    def _handle_data_message(self, device_id: str, packet: ProtocolPacket,
                           interface_type: str):
        """Handle incoming data message"""
        # Check if message is for router or needs forwarding
        if packet.dest_addr == RoutingService.ROUTER_ADDRESS:
            # Message is for the router
            self.logger.info(f"Received data message from device {device_id}",
                           bytes=len(packet.payload))
            
            # Could trigger application-specific handling here
            # For now, just log the message
            try:
                message_text = packet.payload.decode('utf-8', errors='ignore')
                self.logger.debug(f"Message content: {message_text[:100]}...")
            except:
                self.logger.debug(f"Binary message, {len(packet.payload)} bytes")
        
        elif packet.dest_addr == RoutingService.BROADCAST_ADDRESS:
            # Broadcast message - forward to all other devices
            self.logger.info(f"Received broadcast from device {device_id}")
            self.broadcast_message(packet.payload)
        
        else:
            # Forward to specific device
            target_route = self.routing_service.get_route(packet.dest_addr)
            if target_route:
                target_device_id = target_route.device_id
                self.logger.debug(f"Forwarding message from {device_id} to {target_device_id}")
                self.send_message_to_device(target_device_id, packet.payload)
            else:
                self.logger.warning(f"No route for destination address 0x{packet.dest_addr:04X}")
                self.statistics_service.increment_packets_dropped(interface_type)
    
    def get_device_list(self) -> Dict[str, Dict[str, Any]]:
        """Get list of all connected devices with their information"""
        device_list = {}
        
        # Get routing information
        routes = self.routing_service.get_all_routes()
        
        with self.connection_lock:
            for addr, route in routes.items():
                device_id = route.device_id
                
                # Base device info from route
                device_info = {
                    'device_id': device_id,
                    'address': f"0x{addr:04X}",
                    'interface_type': route.interface_type.value,
                    'last_seen': route.last_seen,
                    'connection_info': route.connection_info
                }
                
                # Add connection details if available
                if device_id in self.device_connections:
                    connection = self.device_connections[device_id]
                    device_info.update({
                        'connected_at': connection.get('connected_at'),
                        'authenticated_at': connection.get('authenticated_at'),
                        'assigned_address': connection.get('assigned_address')
                    })
                
                # Add statistics
                device_stats = self.statistics_service.get_device_stats(device_id)
                device_info['statistics'] = device_stats
                
                device_list[device_id] = device_info
        
        return device_list
    
    def get_device_info(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific device"""
        device_list = self.get_device_list()
        return device_list.get(device_id)
    
    def is_device_connected(self, device_id: str) -> bool:
        """Check if a device is currently connected"""
        with self.connection_lock:
            return device_id in self.device_connections
    
    def get_connected_device_count(self) -> int:
        """Get total number of connected devices"""
        return self.routing_service.get_device_count()
    
    def get_connected_device_count_by_interface(self, interface_type: str) -> int:
        """Get number of devices connected via specific interface"""
        from services.routing_service import InterfaceType
        try:
            interface_enum = InterfaceType(interface_type)
            return self.routing_service.get_device_count_by_interface(interface_enum)
        except ValueError:
            return 0