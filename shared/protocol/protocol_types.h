#ifndef PROTOCOL_TYPES_H
#define PROTOCOL_TYPES_H

// Platform-specific includes
#ifdef ARDUINO
#include <Arduino.h>
#else
#include <stdint.h>
#include <cstddef>
#endif

// Protocol constants
#define PROTOCOL_VERSION 1
#define FLAG_ENCRYPTED 0x01
#define HEADER_SIZE 19  // Increased from 18 to 19 (changed checksum from 8-bit to 16-bit)
#define MAX_PAYLOAD_SIZE 256

// Priority levels (2 bits in priority_flags)
#define PRIORITY_LOW 0x00
#define PRIORITY_NORMAL 0x01
#define PRIORITY_HIGH 0x02
#define PRIORITY_CRITICAL 0x03
#define PRIORITY_MASK 0x03

// Fragment flags (in priority_flags byte)
#define FLAG_FRAGMENTED 0x04
#define FLAG_MORE_FRAGMENTS 0x08

// QoS flags (in priority_flags byte)
#define FLAG_QOS_NO_ACK 0x10   // Bit 4: Set = No ACK needed (fire-and-forget)
#define FLAG_QOS_RELIABLE 0x20 // Bit 5: Set = Wait for ACK (reliable delivery)

// Default TTL
#define DEFAULT_TTL 16

// Cryptographic constants
#define HMAC_SIZE 32
#define SESSION_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define NONCE_SIZE 16

// Special addresses (with PROTOCOL_ prefix to avoid conflicts)
#define PROTOCOL_ROUTER_ADDRESS 0x0000
#define PROTOCOL_BROADCAST_ADDRESS 0xFFFF
#define PROTOCOL_UNASSIGNED_ADDRESS 0x0000

// Message types
enum class MessageType : uint8_t
{
    // Handshake messages (0x01-0x04)
    HELLO = 0x01,
    CHALLENGE = 0x02,
    AUTH = 0x03,
    AUTH_ACK = 0x04,
    
    // Data messages (0x05-0x06)
    DATA = 0x05,
    ACK = 0x06,
    
    // Control messages (0x07-0x0F)
    CONTROL = 0x07,
    HEARTBEAT = 0x08,
    DISCONNECT = 0x09,
    DISCONNECT_ACK = 0x0A,
    SESSION_RESUME = 0x0B,
    SESSION_RESUME_ACK = 0x0C,
    SESSION_REKEY_REQ = 0x0D,
    SESSION_REKEY_ACK = 0x0E,
    PING = 0x0F,
    
    // Error messages (0xF0-0xFF)
    ERROR = 0xFF
};

// Transport types
enum class TransportType : uint8_t
{
    WIFI = 0,
    BLE = 1
};

// Universal constants that work for both C++ router and Arduino client
constexpr TransportType TRANSPORT_WIFI = TransportType::WIFI;
constexpr TransportType TRANSPORT_BLE = TransportType::BLE;

constexpr uint8_t MSG_HELLO = static_cast<uint8_t>(MessageType::HELLO);
constexpr uint8_t MSG_CHALLENGE = static_cast<uint8_t>(MessageType::CHALLENGE);
constexpr uint8_t MSG_AUTH = static_cast<uint8_t>(MessageType::AUTH);
constexpr uint8_t MSG_AUTH_ACK = static_cast<uint8_t>(MessageType::AUTH_ACK);
constexpr uint8_t MSG_DATA = static_cast<uint8_t>(MessageType::DATA);
constexpr uint8_t MSG_ACK = static_cast<uint8_t>(MessageType::ACK);
constexpr uint8_t MSG_CONTROL = static_cast<uint8_t>(MessageType::CONTROL);
constexpr uint8_t MSG_HEARTBEAT = static_cast<uint8_t>(MessageType::HEARTBEAT);
constexpr uint8_t MSG_DISCONNECT = static_cast<uint8_t>(MessageType::DISCONNECT);
constexpr uint8_t MSG_DISCONNECT_ACK = static_cast<uint8_t>(MessageType::DISCONNECT_ACK);
constexpr uint8_t MSG_SESSION_RESUME = static_cast<uint8_t>(MessageType::SESSION_RESUME);
constexpr uint8_t MSG_SESSION_RESUME_ACK = static_cast<uint8_t>(MessageType::SESSION_RESUME_ACK);
constexpr uint8_t MSG_SESSION_REKEY_REQ = static_cast<uint8_t>(MessageType::SESSION_REKEY_REQ);
constexpr uint8_t MSG_SESSION_REKEY_ACK = static_cast<uint8_t>(MessageType::SESSION_REKEY_ACK);
constexpr uint8_t MSG_PING = static_cast<uint8_t>(MessageType::PING);
constexpr uint8_t MSG_ERROR = static_cast<uint8_t>(MessageType::ERROR);

constexpr uint16_t ROUTER_ADDRESS = PROTOCOL_ROUTER_ADDRESS;
constexpr uint16_t UNASSIGNED_ADDRESS = PROTOCOL_UNASSIGNED_ADDRESS;
constexpr uint16_t BROADCAST_ADDRESS = PROTOCOL_BROADCAST_ADDRESS;

// Protocol packet structure (for embedded use)
struct BasicProtocolPacket
{
    uint8_t version_flags;
    uint8_t msg_type;
    uint16_t source_addr;
    uint16_t dest_addr;
    uint8_t payload_length;
    uint16_t checksum;
    uint16_t sequence_number;
    uint8_t ttl;
    uint8_t priority_flags;
    uint16_t fragment_id;
    uint32_t timestamp;
    uint8_t payload[MAX_PAYLOAD_SIZE];
};

// Disconnect reason codes (for DISCONNECT message payload)
enum class DisconnectReason : uint8_t
{
    NORMAL_SHUTDOWN = 0x00,      // Clean application shutdown
    GOING_TO_SLEEP = 0x01,       // Device entering sleep mode
    LOW_BATTERY = 0x02,          // Battery critical, preserving power
    NETWORK_SWITCH = 0x03,       // Switching transport (WiFi<->BLE)
    FIRMWARE_UPDATE = 0x04,      // OTA update starting
    USER_REQUEST = 0x05,         // User-initiated disconnect
    ERROR = 0xFF                 // Error condition, unspecified
};

// Error codes (for ERROR message payload)
enum class ErrorCode : uint8_t
{
    INVALID_SEQUENCE = 0x01,     // Sequence number out of window
    STALE_TIMESTAMP = 0x02,      // Timestamp too old
    DECRYPTION_FAILED = 0x03,    // GCM authentication failed
    INVALID_DESTINATION = 0x04,  // Unknown destination address
    TTL_EXPIRED = 0x05,          // Packet TTL reached zero
    RATE_LIMIT_EXCEEDED = 0x06,  // Too many packets from device
    SESSION_EXPIRED = 0x07,      // Session key no longer valid
    MALFORMED_PACKET = 0x08,     // Packet structure invalid
    UNSUPPORTED_VERSION = 0x09,  // Protocol version not supported
    AUTHENTICATION_FAILED = 0x0A // Handshake authentication failed
};

// Control packet types (for CONTROL message payload byte 0)
enum class ControlType : uint8_t
{
    PING = 0x00,                 // Ping request
    PONG = 0x01,                 // Ping response
    TIME_SYNC_REQ = 0x02,        // Request time synchronization
    TIME_SYNC_RES = 0x03,        // Time sync response
    CONFIG_UPDATE = 0x04,        // Configuration update
    FIRMWARE_INFO = 0x05,        // Firmware version info
    CAPABILITIES_REQ = 0x06,     // Request device capabilities
    CAPABILITIES_RES = 0x07      // Capabilities response
};

// Configuration structures
struct NetworkConfig
{
#ifdef ARDUINO
    String router_id;
    String shared_secret;      // Master secret - always derives device PSK
    String device_id;
    // Note: use_device_psk removed - ALWAYS uses device PSK for security
#else
    char router_id[64];
    char shared_secret[32];
    char device_id[32];
#endif
};

#endif // PROTOCOL_TYPES_H