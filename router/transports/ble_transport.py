"""
BLE Transport Layer
Handles BLE scanning, connections, and GATT communication
"""

import asyncio
import threading
import time
from typing import Dict, Optional, Set, Any

from bleak import BleakScanner, BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from core.config import RouterConfig
from core.logger import get_logger
from core.transport_interface import TransportInterface
from services.routing_service import RoutingService, InterfaceType
from services.device_management_service import DeviceManagementService
from services.statistics_service import StatisticsService
from protocol import ProtocolPacket, MessageType, HandshakeManager, PacketCrypto, parse_hello_packet


class BLEDeviceHandler:
    """Handles communication with a single BLE device"""
    
    def __init__(self, device_address: str, config: RouterConfig,
                 routing_service: RoutingService,
                 device_management: DeviceManagementService,
                 statistics_service: StatisticsService):
        self.device_address = device_address
        self.config = config
        self.routing_service = routing_service
        self.device_management = device_management
        self.statistics_service = statistics_service
        self.logger = get_logger(f"{__name__}.{device_address}")
        
        # BLE connection
        self.client: Optional[BleakClient] = None
        self.data_characteristic: Optional[BleakGATTCharacteristic] = None
        
        # Device state
        self.device_id: Optional[str] = None
        self.assigned_address: Optional[int] = None
        self.session_crypto: Optional[PacketCrypto] = None
        self.authenticated = False
        self.handshake_manager = HandshakeManager(config.router_id, config.shared_secret)
        
        # Connection state
        self.connected = False
        self.running = False
        
        self.logger.debug("BLE device handler created")
    
    async def connect_and_setup(self) -> bool:
        """Connect to BLE device and setup GATT services"""
        try:
            self.logger.info("Connecting to BLE device")
            
            # Connect to device
            self.client = BleakClient(self.device_address)
            await self.client.connect(timeout=10.0)
            
            if not self.client.is_connected:
                self.logger.error("Failed to connect to BLE device")
                return False
            
            self.connected = True
            self.logger.info("Connected to BLE device")
            
            # Discover services
            # Access services directly from the client
            service = self.client.services.get_service(self.config.ble.service_uuid)
            if not service:
                self.logger.error("Custom service not found on BLE device")
                await self.disconnect()
                return False
            
            self.data_characteristic = service.get_characteristic(self.config.ble.characteristic_uuid)
            if not self.data_characteristic:
                self.logger.error("Data characteristic not found on BLE device")
                await self.disconnect()
                return False
            
            # Enable notifications
            await self.client.start_notify(self.data_characteristic, self._notification_handler)
            
            self.logger.info("BLE device setup completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Error connecting to BLE device: {e}", exc_info=True)
            await self.disconnect()
            return False
    
    async def disconnect(self):
        """Disconnect from BLE device"""
        if self.client and self.client.is_connected:
            try:
                if self.data_characteristic:
                    await self.client.stop_notify(self.data_characteristic)
                await self.client.disconnect()
                self.logger.info("Disconnected from BLE device")
            except Exception as e:
                self.logger.debug(f"Error during disconnect: {e}")
        
        self.connected = False
        self.running = False
        
        # Notify device management
        if self.device_id:
            self.device_management.handle_device_disconnected(self.device_id)
    
    def _notification_handler(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        """Handle incoming notifications from BLE device"""
        try:
            if not data:
                return
            
            self.logger.debug(f"Received BLE notification, {len(data)} bytes")
            
            # Parse packet
            packet = ProtocolPacket.from_bytes(bytes(data))
            
            if not self.authenticated:
                # Still in handshake phase
                self._handle_handshake_packet(packet)
            else:
                # Normal communication
                self._handle_data_packet(packet)
                
        except Exception as e:
            self.logger.error(f"Error handling BLE notification: {e}", exc_info=True)
            self.statistics_service.increment_errors('ble')
    
    def _handle_handshake_packet(self, packet: ProtocolPacket):
        """Handle handshake packets"""
        try:
            if packet.msg_type == MessageType.HELLO:
                # Parse HELLO packet
                router_id, device_id, nonce = parse_hello_packet(packet)
                
                if router_id != self.config.router_id:
                    self.logger.warning(f"Wrong router ID from device: {router_id}")
                    return
                
                self.device_id = device_id
                self.logger.info(f"Received HELLO from BLE device {device_id}")
                
                # Store the client nonce
                self.handshake_manager.pending_handshakes[device_id] = {'nonce1': nonce}
                
                # Send CHALLENGE
                challenge_packet = self.handshake_manager.create_challenge_packet(device_id)
                asyncio.create_task(self._send_packet(challenge_packet))
                
                self.logger.debug(f"Sent CHALLENGE to BLE device {device_id}")
            
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
                        interface_type=InterfaceType.BLE,
                        connection_handle=self.client,
                        session_crypto=self.session_crypto,
                        connection_info={
                            'ble_address': self.device_address,
                            'service_uuid': self.config.ble.service_uuid,
                            'characteristic_uuid': self.config.ble.characteristic_uuid
                        }
                    )
                    
                    # Send AUTH_ACK
                    asyncio.create_task(self._send_packet(auth_ack_packet))
                    
                    # Mark as authenticated
                    self.authenticated = True
                    
                    # Notify device management
                    self.device_management.handle_device_connected(
                        self.device_id, 'ble', {'address': self.device_address}
                    )
                    
                    self.device_management.handle_handshake_completed(
                        self.device_id, self.assigned_address, 'ble'
                    )
                    
                    self.running = True
                    self.logger.info(f"BLE device {self.device_id} authenticated",
                                   address=f"0x{self.assigned_address:04X}")
                else:
                    # Authentication failed
                    self.device_management.handle_handshake_failed(
                        self.device_id, 'ble', 'Authentication verification failed'
                    )
                    self.logger.warning(f"Authentication failed for BLE device {self.device_id}")
            
        except Exception as e:
            self.logger.error(f"Error handling handshake packet: {e}", exc_info=True)
            self.statistics_service.increment_errors('ble')
    
    def _handle_data_packet(self, packet: ProtocolPacket):
        """Handle data packets from authenticated device"""
        try:
            # Decrypt packet if needed
            if packet.flags & 0x01:  # Encrypted flag
                if self.session_crypto:
                    packet.payload = self.session_crypto.decrypt_payload(packet.payload)
            
            # Handle the message through device management
            self.device_management.handle_incoming_message(
                self.device_id, packet, 'ble'
            )
            
        except Exception as e:
            self.logger.error(f"Error handling data packet: {e}", exc_info=True)
            self.statistics_service.increment_errors('ble')
    
    async def _send_packet(self, packet: ProtocolPacket) -> bool:
        """Send a packet to the BLE device"""
        try:
            if not self.client or not self.client.is_connected or not self.data_characteristic:
                self.logger.warning("Cannot send packet - BLE device not connected")
                return False
            
            data = packet.to_bytes()
            await self.client.write_gatt_char(self.data_characteristic, data, response=True)
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending BLE packet: {e}")
            return False
    
    async def send_message(self, packet: ProtocolPacket) -> bool:
        """Send a message packet to this BLE device"""
        try:
            # Encrypt if needed and session crypto is available
            if self.session_crypto and packet.flags & 0x01:
                packet.payload = self.session_crypto.encrypt(packet.payload)
            
            return await self._send_packet(packet)
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")
            return False


class BLETransport(TransportInterface):
    """BLE transport layer implementation"""
    
    def __init__(self, config: RouterConfig, routing_service: RoutingService,
                 device_management: DeviceManagementService,
                 statistics_service: StatisticsService):
        self.config = config
        self.routing_service = routing_service
        self.device_management = device_management
        self.statistics_service = statistics_service
        self.logger = get_logger(__name__)
        
        # BLE state
        self.running = False
        self.scan_task: Optional[asyncio.Task] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.ble_thread: Optional[threading.Thread] = None
        
        # Device handlers
        self.device_handlers: Dict[str, BLEDeviceHandler] = {}
        self.seen_devices: Set[str] = set()
        
        # Register message handler
        self.device_management.register_message_handler('ble', self._send_to_device)
        
        self.logger.info("BLE transport initialized",
                        service_uuid=config.ble.service_uuid,
                        scan_interval=config.ble.scan_interval)
    
    def start(self) -> bool:
        """Start the BLE transport"""
        if self.running:
            return True
        
        try:
            self.running = True
            
            # Start BLE thread with event loop
            self.ble_thread = threading.Thread(
                target=self._run_ble_loop,
                daemon=True,
                name="BLETransport"
            )
            self.ble_thread.start()
            
            # Wait a bit for the loop to start
            time.sleep(1)
            
            self.logger.info("BLE transport started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start BLE transport: {e}", exc_info=True)
            self.stop()
            return False
    
    def stop(self):
        """Stop the BLE transport"""
        if not self.running:
            return
        
        self.logger.info("Stopping BLE transport...")
        self.running = False
        
        # Stop scanning task
        if self.loop and self.scan_task:
            self.loop.call_soon_threadsafe(self.scan_task.cancel)
        
        # Disconnect all devices
        if self.loop:
            for handler in self.device_handlers.values():
                self.loop.call_soon_threadsafe(
                    lambda h=handler: asyncio.create_task(h.disconnect())
                )
        
        # Wait for BLE thread
        if self.ble_thread and self.ble_thread.is_alive():
            self.ble_thread.join(timeout=10)
        
        self.device_handlers.clear()
        self.seen_devices.clear()
        
        self.logger.info("BLE transport stopped")
    
    def is_running(self) -> bool:
        """Check if transport is running"""
        return self.running
    
    def _run_ble_loop(self):
        """Run the BLE event loop in a separate thread"""
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            
            self.logger.debug("BLE event loop started")
            
            # Start scanning task
            self.scan_task = self.loop.create_task(self._scan_loop())
            
            # Run the event loop
            self.loop.run_until_complete(self.scan_task)
            
        except asyncio.CancelledError:
            self.logger.debug("BLE scan task cancelled")
        except Exception as e:
            self.logger.error(f"Error in BLE event loop: {e}", exc_info=True)
        finally:
            self.logger.debug("BLE event loop stopped")
    
    async def _scan_loop(self):
        """Main BLE scanning loop"""
        self.logger.debug("Starting BLE scan loop")
        
        while self.running:
            try:
                await self._scan_for_devices()
                
                # Pause between scans
                await asyncio.sleep(self.config.ble.scan_pause)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in scan loop: {e}")
                await asyncio.sleep(5)  # Wait before retrying
    
    async def _scan_for_devices(self):
        """Scan for BLE devices advertising our router ID"""
        try:
            self.logger.debug("Scanning for BLE devices...")
            
            # Scan for devices
            devices = await BleakScanner.discover(timeout=self.config.ble.scan_interval)
            
            for device in devices:
                if not self.running:
                    break
                
                # Check if device name contains our router ID
                if device.name and self.config.router_id in device.name:
                    device_address = device.address
                    
                    # Skip if already connected
                    if device_address in self.device_handlers:
                        continue
                    
                    # Skip if already seen recently
                    if device_address in self.seen_devices:
                        continue
                    
                    self.logger.info(f"Found potential IoT device",
                                   name=device.name,
                                   address=device_address)
                    
                    # Mark as seen
                    self.seen_devices.add(device_address)
                    
                    # Try to connect
                    await self._connect_to_device(device_address)
                    
                    # Limit concurrent connections
                    if len(self.device_handlers) >= self.config.ble.max_connections:
                        break
            
            self.logger.debug(f"Scan completed, found {len(devices)} devices")
            
        except Exception as e:
            self.logger.error(f"Error scanning for devices: {e}")
    
    async def _connect_to_device(self, device_address: str):
        """Connect to a BLE device"""
        try:
            # Create device handler
            handler = BLEDeviceHandler(
                device_address=device_address,
                config=self.config,
                routing_service=self.routing_service,
                device_management=self.device_management,
                statistics_service=self.statistics_service
            )
            
            # Try to connect
            if await handler.connect_and_setup():
                self.device_handlers[device_address] = handler
                self.logger.info(f"Successfully connected to BLE device {device_address}")
            else:
                self.logger.warning(f"Failed to connect to BLE device {device_address}")
                await handler.disconnect()
                
        except Exception as e:
            self.logger.error(f"Error connecting to BLE device {device_address}: {e}")
    
    def _send_to_device(self, device_id: str, packet: ProtocolPacket) -> bool:
        """Send a packet to a specific BLE device"""
        # Find device handler
        for handler in self.device_handlers.values():
            if handler.device_id == device_id:
                if self.loop:
                    # Schedule the send operation
                    future = asyncio.run_coroutine_threadsafe(
                        handler.send_message(packet), self.loop
                    )
                    try:
                        return future.result(timeout=5.0)
                    except:
                        return False
                return False
        
        self.logger.warning(f"No BLE connection found for device {device_id}")
        return False
    
    def get_connected_devices(self) -> Dict[str, Any]:
        """Get list of connected BLE devices"""
        devices = {}
        for address, handler in self.device_handlers.items():
            if handler.device_id and handler.assigned_address is not None:
                devices[handler.device_id] = {
                    'address': f"0x{handler.assigned_address:04X}",
                    'ble_address': address,
                    'connected': handler.connected,
                    'interface': 'ble'
                }
        return devices