"""
Multi-Protocol IoT Network - Protocol Implementation
Defines packet structure, message types, and core protocol logic
"""

import struct
import hashlib
import hmac
import secrets
from typing import Optional, Dict, Any, Tuple
from enum import IntEnum
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class MessageType(IntEnum):
    """Protocol message types"""
    HELLO = 0x01
    CHALLENGE = 0x02
    AUTH = 0x03
    AUTH_ACK = 0x04
    DATA = 0x05
    ACK = 0x06
    CONTROL = 0x07
    ERROR = 0xFF

class ProtocolVersion:
    """Protocol version and flags"""
    VERSION = 1
    FLAG_ENCRYPTED = 0x01

class ProtocolPacket:
    """Protocol packet structure: 8-byte header + variable payload"""

    HEADER_SIZE = 8
    MAX_PAYLOAD_SIZE = 256

    def __init__(self, msg_type: MessageType, source_addr: int = 0,
                 dest_addr: int = 0, payload: bytes = b'', encrypted: bool = False):
        self.version = ProtocolVersion.VERSION
        self.flags = ProtocolVersion.FLAG_ENCRYPTED if encrypted else 0
        self.msg_type = msg_type
        self.source_addr = source_addr
        self.dest_addr = dest_addr
        self.payload = payload

        if len(payload) > self.MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload too large: {len(payload)} > {self.MAX_PAYLOAD_SIZE}")

    def to_bytes(self) -> bytes:
        """Serialize packet to bytes"""
        version_flags = (self.version << 4) | (self.flags & 0x0F)
        header = struct.pack('!BBHHBB',
                           version_flags,
                           self.msg_type,
                           self.source_addr,
                           self.dest_addr,
                           len(self.payload),
                           0)  # reserved byte
        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ProtocolPacket':
        """Deserialize packet from bytes"""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Insufficient data for header")

        version_flags, msg_type, source_addr, dest_addr, payload_len, reserved = struct.unpack('!BBHHBB', data[:cls.HEADER_SIZE])

        version = (version_flags >> 4) & 0x0F
        flags = version_flags & 0x0F
        encrypted = bool(flags & ProtocolVersion.FLAG_ENCRYPTED)

        if version != ProtocolVersion.VERSION:
            raise ValueError(f"Unsupported protocol version: {version}")

        if len(data) < cls.HEADER_SIZE + payload_len:
            raise ValueError("Insufficient data for payload")

        payload = data[cls.HEADER_SIZE:cls.HEADER_SIZE + payload_len]

        packet = cls(MessageType(msg_type), source_addr, dest_addr, payload, encrypted)
        return packet

class HandshakeManager:
    """Manages protocol handshake and authentication"""

    def __init__(self, router_id: str, shared_secret: str):
        self.router_id = router_id
        self.shared_secret = shared_secret.encode('utf-8')
        self.pending_handshakes: Dict[str, Dict[str, Any]] = {}

    def create_hello_packet(self, device_id: str) -> ProtocolPacket:
        """Create HELLO packet for device joining network"""
        nonce1 = secrets.randbits(32)

        # Payload: RID_length | RID | DeviceID_length | DeviceID | Nonce1
        rid_bytes = self.router_id.encode('utf-8')
        device_id_bytes = device_id.encode('utf-8')

        payload = struct.pack('!B', len(rid_bytes)) + rid_bytes
        payload += struct.pack('!B', len(device_id_bytes)) + device_id_bytes
        payload += struct.pack('!I', nonce1)

        # Store nonce for later use
        self.pending_handshakes[device_id] = {'nonce1': nonce1}

        return ProtocolPacket(MessageType.HELLO, 0x0000, 0x0000, payload)

    def create_challenge_packet(self, device_id: str) -> ProtocolPacket:
        """Create CHALLENGE packet in response to HELLO"""
        nonce2 = secrets.randbits(32)

        if device_id not in self.pending_handshakes:
            raise ValueError(f"No pending handshake for device: {device_id}")

        self.pending_handshakes[device_id]['nonce2'] = nonce2

        payload = struct.pack('!I', nonce2)
        return ProtocolPacket(MessageType.CHALLENGE, 0x0000, 0x0000, payload)

    def create_auth_packet(self, device_id: str, nonce2: int) -> ProtocolPacket:
        """Create AUTH packet with HMAC proof"""
        if device_id not in self.pending_handshakes:
            raise ValueError(f"No pending handshake for device: {device_id}")

        nonce1 = self.pending_handshakes[device_id]['nonce1']

        # Compute HMAC of nonce2 + device_id + router_id
        hmac_data = struct.pack('!I', nonce2) + device_id.encode('utf-8') + self.router_id.encode('utf-8')
        auth_tag = hmac.new(self.shared_secret, hmac_data, hashlib.sha256).digest()[:16]  # Truncate to 16 bytes

        payload = auth_tag + struct.pack('!I', nonce1)
        return ProtocolPacket(MessageType.AUTH, 0x0000, 0x0000, payload)

    def create_auth_ack_packet(self, device_id: str, assigned_addr: int) -> ProtocolPacket:
        """Create AUTH_ACK packet to complete handshake"""
        if device_id not in self.pending_handshakes:
            raise ValueError(f"No pending handshake for device: {device_id}")

        nonce1 = self.pending_handshakes[device_id]['nonce1']

        # Compute HMAC of nonce1 to prove router has shared secret
        hmac_data = struct.pack('!I', nonce1)
        auth_tag = hmac.new(self.shared_secret, hmac_data, hashlib.sha256).digest()[:16]

        payload = auth_tag + struct.pack('!H', assigned_addr)
        return ProtocolPacket(MessageType.AUTH_ACK, 0x0000, assigned_addr, payload)

    def verify_auth_packet(self, device_id: str, auth_packet: ProtocolPacket) -> bool:
        """Verify AUTH packet from device"""
        if device_id not in self.pending_handshakes:
            return False

        if len(auth_packet.payload) < 20:  # 16 bytes HMAC + 4 bytes nonce
            return False

        received_tag = auth_packet.payload[:16]
        received_nonce1 = struct.unpack('!I', auth_packet.payload[16:20])[0]

        # Verify nonce1 matches
        expected_nonce1 = self.pending_handshakes[device_id]['nonce1']
        if received_nonce1 != expected_nonce1:
            return False

        # Compute expected HMAC
        nonce2 = self.pending_handshakes[device_id]['nonce2']
        hmac_data = struct.pack('!I', nonce2) + device_id.encode('utf-8') + self.router_id.encode('utf-8')
        expected_tag = hmac.new(self.shared_secret, hmac_data, hashlib.sha256).digest()[:16]

        return hmac.compare_digest(received_tag, expected_tag)

    def derive_session_key(self, device_id: str) -> bytes:
        """Derive session key from nonces and shared secret"""
        if device_id not in self.pending_handshakes:
            raise ValueError(f"No pending handshake for device: {device_id}")

        nonce1 = self.pending_handshakes[device_id]['nonce1']
        nonce2 = self.pending_handshakes[device_id]['nonce2']

        key_data = struct.pack('!II', nonce1, nonce2)
        session_key = hmac.new(self.shared_secret, key_data, hashlib.sha256).digest()[:16]  # 128-bit AES key

        return session_key

    def complete_handshake(self, device_id: str) -> bytes:
        """Complete handshake and return session key"""
        session_key = self.derive_session_key(device_id)
        del self.pending_handshakes[device_id]  # Clean up
        return session_key

class PacketCrypto:
    """Handles packet encryption and decryption"""

    def __init__(self, session_key: bytes):
        self.session_key = session_key
        self.iv_counter = 0

    def encrypt_payload(self, payload: bytes) -> bytes:
        """Encrypt payload using AES-CBC"""
        # Generate IV from counter (in practice, should be more secure)
        iv = self.iv_counter.to_bytes(16, 'big')
        self.iv_counter += 1

        cipher = AES.new(self.session_key, AES.MODE_CBC, iv)

        # Pad payload to multiple of 16 bytes
        padding_len = 16 - (len(payload) % 16)
        padded_payload = payload + bytes([padding_len] * padding_len)

        encrypted = cipher.encrypt(padded_payload)
        return iv + encrypted  # Prepend IV

    def decrypt_payload(self, encrypted_payload: bytes) -> bytes:
        """Decrypt payload using AES-CBC"""
        if len(encrypted_payload) < 16:
            raise ValueError("Encrypted payload too short")

        iv = encrypted_payload[:16]
        encrypted = encrypted_payload[16:]

        cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
        padded_payload = cipher.decrypt(encrypted)

        # Remove padding
        padding_len = padded_payload[-1]
        if padding_len > 16 or padding_len == 0:
            raise ValueError("Invalid padding")

        payload = padded_payload[:-padding_len]
        return payload

def parse_hello_packet(packet: ProtocolPacket) -> Tuple[str, str, int]:
    """Parse HELLO packet payload"""
    if packet.msg_type != MessageType.HELLO:
        raise ValueError("Not a HELLO packet")

    payload = packet.payload
    offset = 0

    # Parse RID
    rid_len = payload[offset]
    offset += 1
    router_id = payload[offset:offset + rid_len].decode('utf-8')
    offset += rid_len

    # Parse Device ID
    device_id_len = payload[offset]
    offset += 1
    device_id = payload[offset:offset + device_id_len].decode('utf-8')
    offset += device_id_len

    # Parse Nonce1
    nonce1 = struct.unpack('!I', payload[offset:offset + 4])[0]

    return router_id, device_id, nonce1

def parse_challenge_packet(packet: ProtocolPacket) -> int:
    """Parse CHALLENGE packet payload"""
    if packet.msg_type != MessageType.CHALLENGE:
        raise ValueError("Not a CHALLENGE packet")

    return struct.unpack('!I', packet.payload[:4])[0]

def parse_auth_ack_packet(packet: ProtocolPacket) -> Tuple[bytes, int]:
    """Parse AUTH_ACK packet payload"""
    if packet.msg_type != MessageType.AUTH_ACK:
        raise ValueError("Not an AUTH_ACK packet")

    auth_tag = packet.payload[:16]
    assigned_addr = struct.unpack('!H', packet.payload[16:18])[0]

    return auth_tag, assigned_addr