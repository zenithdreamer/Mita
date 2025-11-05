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
#define HEADER_SIZE 16
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
    HELLO = 0x01,
    CHALLENGE = 0x02,
    AUTH = 0x03,
    AUTH_ACK = 0x04,
    DATA = 0x05,
    ACK = 0x06,
    CONTROL = 0x07,
    HEARTBEAT = 0x08,
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
    uint8_t checksum;
    uint16_t sequence_number;
    uint8_t ttl;
    uint8_t priority_flags;
    uint16_t fragment_id;
    uint16_t timestamp;
    uint8_t payload[MAX_PAYLOAD_SIZE];
};

// Configuration structures
struct NetworkConfig
{
#ifdef ARDUINO
    String router_id;
    String shared_secret;
    String device_id;
#else
    char router_id[64];
    char shared_secret[32];
    char device_id[32];
#endif
};

#endif // PROTOCOL_TYPES_H