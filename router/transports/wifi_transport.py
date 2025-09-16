"""
WiFi Transport Layer
Handles WiFi AP setup and client connections via TCP
"""

import socket
import threading
import time
import subprocess
from typing import Dict, Optional, Any

from core.config import RouterConfig
from core.logger import get_logger
from core.transport_interface import TransportInterface
from services.routing_service import RoutingService, InterfaceType
from services.device_management_service import DeviceManagementService
from services.statistics_service import StatisticsService
from protocol import ProtocolPacket, MessageType, HandshakeManager, PacketCrypto, parse_hello_packet


class WiFiClientHandler:
    """Handles communication with a single WiFi client"""
    
    def __init__(self, client_socket: socket.socket, client_address: tuple,
                 config: RouterConfig, routing_service: RoutingService,
                 device_management: DeviceManagementService,
                 statistics_service: StatisticsService):
        self.client_socket = client_socket
        self.client_address = client_address
        self.config = config
        self.routing_service = routing_service
        self.device_management = device_management
        self.statistics_service = statistics_service
        self.logger = get_logger(f"{__name__}.{client_address[0]}")
        
        self.handshake_manager = HandshakeManager(config.router_id, config.shared_secret)
        self.device_id: Optional[str] = None
        self.assigned_address: Optional[int] = None
        self.session_crypto: Optional[PacketCrypto] = None
        self.authenticated = False
        self.running = False
        
        self.logger.debug("WiFi client handler created", address=str(client_address))
    
    def start(self):
        """Start handling client communication"""
        self.running = True
        try:
            self._handle_client()
        except Exception as e:
            self.logger.error(f"Error handling client: {e}", exc_info=True)
        finally:
            self._cleanup()
    
    def stop(self):
        """Stop handling client communication"""
        self.running = False
        try:
            self.client_socket.close()
        except:
            pass
    
    def _handle_client(self):
        """Main client handling loop"""
        self.logger.info("Started handling WiFi client")
        
        # Set socket timeout for non-blocking operations
        self.client_socket.settimeout(1.0)
        
        while self.running:
            try:
                # Receive packet
                packet = self._receive_packet()
                if packet is None:
                    continue
                
                if not self.authenticated:
                    # Still in handshake phase
                    self._handle_handshake_packet(packet)
                else:
                    # Normal communication
                    self._handle_data_packet(packet)
                    
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"Error in client loop: {e}")
                break
    
    def _receive_packet(self) -> Optional[ProtocolPacket]:
        """Receive a packet from the client"""
        try:
            # Read header first
            header_data = self._receive_exact(ProtocolPacket.HEADER_SIZE)
            if not header_data:
                return None
            
            # Extract payload length from header (byte 6)
            payload_length = header_data[6]
            
            # Read payload if present
            full_data = header_data
            if payload_length > 0:
                payload_data = self._receive_exact(payload_length)
                if not payload_data:
                    return None
                full_data += payload_data
            
            # Parse complete packet
            packet = ProtocolPacket.from_bytes(full_data)
            return packet
            
        except Exception as e:
            self.logger.debug(f"Error receiving packet: {e}")
            return None
    
    def _receive_exact(self, size: int) -> Optional[bytes]:
        """Receive exact number of bytes"""
        data = b''
        while len(data) < size and self.running:
            try:
                chunk = self.client_socket.recv(size - len(data))
                if not chunk:
                    return None
                data += chunk
            except socket.timeout:
                continue
            except Exception:
                return None
        
        return data if len(data) == size else None
    
    def _handle_handshake_packet(self, packet: ProtocolPacket):
        """Handle handshake packets"""
        try:
            if packet.msg_type == MessageType.HELLO:
                # Parse HELLO packet
                router_id, device_id, nonce = parse_hello_packet(packet)
                
                if router_id != self.config.router_id:
                    self.logger.warning(f"Wrong router ID from client: {router_id}")
                    return
                
                self.device_id = device_id
                self.logger.info(f"Received HELLO from device {device_id}")
                
                # Store the client nonce
                self.handshake_manager.pending_handshakes[device_id] = {'nonce1': nonce}
                
                # Send CHALLENGE
                challenge_packet = self.handshake_manager.create_challenge_packet(device_id)
                self._send_packet(challenge_packet)
                
                self.logger.debug(f"Sent CHALLENGE to device {device_id}")
            
            elif packet.msg_type == MessageType.AUTH:
                if not self.device_id:
                    self.logger.warning("Received AUTH without HELLO")
                    return
                
                # Verify authentication
                if self.handshake_manager.verify_auth_packet(self.device_id, packet):
                    # Authentication successful, assign address
                    self.assigned_address = self.routing_service.allocate_address(self.device_id)
                    
                    # Create AUTH_ACK before completing handshake (which cleans up state)
                    auth_ack_packet = self.handshake_manager.create_auth_ack_packet(
                        self.device_id, self.assigned_address
                    )
                    
                    # Complete handshake and get session key
                    session_key = self.handshake_manager.complete_handshake(self.device_id)
                    self.session_crypto = PacketCrypto(session_key)
                    
                    # Add to routing table
                    self.routing_service.add_route(
                        device_id=self.device_id,
                        interface_type=InterfaceType.WIFI,
                        connection_handle=self.client_socket,
                        session_crypto=self.session_crypto,
                        connection_info={
                            'client_ip': self.client_address[0],
                            'client_port': self.client_address[1]
                        }
                    )
                    
                    # Send AUTH_ACK
                    self._send_packet(auth_ack_packet)
                    
                    # Mark as authenticated
                    self.authenticated = True
                    
                    # Notify device management
                    self.device_management.handle_device_connected(
                        self.device_id, 'wifi', {'address': self.client_address}
                    )
                    
                    self.device_management.handle_handshake_completed(
                        self.device_id, self.assigned_address, 'wifi'
                    )
                    
                    self.logger.info(f"Device {self.device_id} authenticated",
                                   address=f"0x{self.assigned_address:04X}")
                else:
                    # Authentication failed
                    self.device_management.handle_handshake_failed(
                        self.device_id, 'wifi', 'Authentication verification failed'
                    )
                    self.logger.warning(f"Authentication failed for device {self.device_id}")
                    self.running = False
            
        except Exception as e:
            self.logger.error(f"Error handling handshake packet: {e}", exc_info=True)
            self.statistics_service.increment_errors('wifi')
    
    def _handle_data_packet(self, packet: ProtocolPacket):
        """Handle data packets from authenticated device"""
        try:
            # Decrypt packet if needed
            if packet.flags & 0x01:  # Encrypted flag
                if self.session_crypto:
                    packet.payload = self.session_crypto.decrypt_payload(packet.payload)
            
            # Handle the message through device management
            self.device_management.handle_incoming_message(
                self.device_id, packet, 'wifi'
            )
            
        except Exception as e:
            self.logger.error(f"Error handling data packet: {e}", exc_info=True)
            self.statistics_service.increment_errors('wifi')
    
    def _send_packet(self, packet: ProtocolPacket) -> bool:
        """Send a packet to the client"""
        try:
            data = packet.to_bytes()
            self.client_socket.sendall(data)
            return True
        except Exception as e:
            self.logger.error(f"Error sending packet: {e}")
            return False
    
    def send_message(self, packet: ProtocolPacket) -> bool:
        """Send a message packet to this client"""
        try:
            # Encrypt if needed and session crypto is available
            if self.session_crypto and packet.flags & 0x01:
                packet.payload = self.session_crypto.encrypt(packet.payload)
            
            return self._send_packet(packet)
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")
            return False
    
    def _cleanup(self):
        """Clean up client connection"""
        try:
            self.client_socket.close()
        except:
            pass
        
        if self.device_id:
            self.device_management.handle_device_disconnected(self.device_id)
        
        self.logger.info("WiFi client handler stopped")


class WiFiTransport(TransportInterface):
    """WiFi transport layer implementation"""
    
    def __init__(self, config: RouterConfig, routing_service: RoutingService,
                 device_management: DeviceManagementService,
                 statistics_service: StatisticsService):
        self.config = config
        self.routing_service = routing_service
        self.device_management = device_management
        self.statistics_service = statistics_service
        self.logger = get_logger(__name__)
        
        # Server state
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.accept_thread: Optional[threading.Thread] = None
        
        # Client handlers
        self.client_handlers: Dict[str, WiFiClientHandler] = {}
        self.client_threads: Dict[str, threading.Thread] = {}
        
        # Register message handler
        self.device_management.register_message_handler('wifi', self._send_to_device)
        
        self.logger.info("WiFi transport initialized",
                        host=config.wifi.server_host,
                        port=config.wifi.server_port)
    
    def start(self) -> bool:
        """Start the WiFi transport"""
        if self.running:
            return True
        
        try:
            # Create and bind server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config.wifi.server_host, self.config.wifi.server_port))
            self.server_socket.listen(self.config.wifi.max_connections)
            
            self.running = True
            
            # Start accept thread
            self.accept_thread = threading.Thread(
                target=self._accept_connections,
                daemon=True,
                name="WiFiAccept"
            )
            self.accept_thread.start()
            
            self.logger.info("WiFi transport started",
                           listening=f"{self.config.wifi.server_host}:{self.config.wifi.server_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start WiFi transport: {e}", exc_info=True)
            self.stop()
            return False
    
    def stop(self):
        """Stop the WiFi transport"""
        if not self.running:
            return
        
        self.logger.info("Stopping WiFi transport...")
        self.running = False
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # Stop all client handlers
        for handler in self.client_handlers.values():
            handler.stop()
        
        # Wait for accept thread
        if self.accept_thread and self.accept_thread.is_alive():
            self.accept_thread.join(timeout=5)
        
        # Wait for client threads
        for thread in self.client_threads.values():
            if thread.is_alive():
                thread.join(timeout=2)
        
        self.client_handlers.clear()
        self.client_threads.clear()
        
        self.logger.info("WiFi transport stopped")
    
    def is_running(self) -> bool:
        """Check if transport is running"""
        return self.running
    
    def _accept_connections(self):
        """Accept incoming client connections"""
        self.logger.debug("WiFi accept thread started")
        
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                
                if not self.running:
                    client_socket.close()
                    break
                
                client_key = f"{client_address[0]}:{client_address[1]}"
                
                self.logger.info(f"New WiFi client connection", address=str(client_address))
                
                # Create client handler
                handler = WiFiClientHandler(
                    client_socket=client_socket,
                    client_address=client_address,
                    config=self.config,
                    routing_service=self.routing_service,
                    device_management=self.device_management,
                    statistics_service=self.statistics_service
                )
                
                # Start client thread
                client_thread = threading.Thread(
                    target=handler.start,
                    daemon=True,
                    name=f"WiFiClient-{client_address[0]}"
                )
                
                self.client_handlers[client_key] = handler
                self.client_threads[client_key] = client_thread
                client_thread.start()
                
                # Clean up finished threads
                self._cleanup_finished_threads()
                
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error accepting connection: {e}")
                    time.sleep(1)
    
    def _cleanup_finished_threads(self):
        """Clean up finished client threads"""
        finished_keys = []
        for key, thread in self.client_threads.items():
            if not thread.is_alive():
                finished_keys.append(key)
        
        for key in finished_keys:
            self.client_handlers.pop(key, None)
            self.client_threads.pop(key, None)
    
    def _send_to_device(self, device_id: str, packet: ProtocolPacket) -> bool:
        """Send a packet to a specific device"""
        # Find client handler for device
        for handler in self.client_handlers.values():
            if handler.device_id == device_id:
                return handler.send_message(packet)
        
        self.logger.warning(f"No WiFi connection found for device {device_id}")
        return False
    
    def get_connected_devices(self) -> Dict[str, Any]:
        """Get list of connected WiFi devices"""
        devices = {}
        for handler in self.client_handlers.values():
            if handler.device_id and handler.assigned_address is not None:
                devices[handler.device_id] = {
                    'address': f"0x{handler.assigned_address:04X}",
                    'client_ip': handler.client_address[0],
                    'client_port': handler.client_address[1],
                    'interface': 'wifi'
                }
        return devices


def get_wlan0_ip() -> str:
    """Get the IP address of wlan0 interface"""
    try:
        result = subprocess.run(['ip', 'addr', 'show', 'wlan0'],
                              capture_output=True, text=True)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'inet ' in line and 'scope global' in line:
                    ip = line.strip().split()[1].split('/')[0]
                    return ip
    except Exception as e:
        pass

    # Fallback to default AP address
    return "192.168.50.1"