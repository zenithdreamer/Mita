#ifndef PROTOCOL_TYPES_H
#define PROTOCOL_TYPES_H

#include <Arduino.h>

// Protocol constants
#define PROTOCOL_VERSION 1
#define FLAG_ENCRYPTED 0x01
#define HEADER_SIZE 8
#define MAX_PAYLOAD_SIZE 256

// Cryptographic constants
#define HMAC_SIZE 32
#define SESSION_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define NONCE_SIZE 4

// Special addresses
#define ROUTER_ADDRESS 0x0000
#define BROADCAST_ADDRESS 0xFFFF
#define UNASSIGNED_ADDRESS 0x0000

// Message types
enum MessageType
{
    MSG_HELLO = 0x01,
    MSG_CHALLENGE = 0x02,
    MSG_AUTH = 0x03,
    MSG_AUTH_ACK = 0x04,
    MSG_DATA = 0x05,
    MSG_ACK = 0x06,
    MSG_CONTROL = 0x07,
    MSG_ERROR = 0xFF
};

// Transport types
enum TransportType
{
    TRANSPORT_WIFI,
    TRANSPORT_BLE
};

// Protocol packet structure
struct ProtocolPacket
{
    uint8_t version_flags;
    uint8_t msg_type;
    uint16_t source_addr;
    uint16_t dest_addr;
    uint8_t payload_length;
    uint8_t reserved;
    uint8_t payload[MAX_PAYLOAD_SIZE];
};

// Configuration structures
struct NetworkConfig
{
    String router_id;
    String shared_secret;
    String device_id;
};

#endif // PROTOCOL_TYPES_H