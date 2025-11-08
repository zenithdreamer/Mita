#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include "protocol_types.h"
#include <string.h>

#if !defined(ESP_PLATFORM) && !defined(ARDUINO)
#include <vector>
#endif

class PacketUtils {
public:
    
    // NOTE: CRC-16 is for basic transport-level integrity checking only
    // This is NOT cryptographically secure and should not be relied upon for security
    // Use AES-GCM authentication tags for cryptographic integrity protection
    
    // CRC-16-CCITT polynomial: 0x1021
    // Used for better error detection than simple checksum
    static uint16_t computeCRC16(const uint8_t* data, size_t length) {
        uint16_t crc = 0xFFFF;  // Initial value
        
        for (size_t i = 0; i < length; i++) {
            crc ^= (uint16_t)data[i] << 8;
            for (uint8_t j = 0; j < 8; j++) {
                if (crc & 0x8000) {
                    crc = (crc << 1) ^ 0x1021;  // Polynomial
                } else {
                    crc = crc << 1;
                }
            }
        }
        
        return crc;
    }
    
    // Compute CRC-16 checksum from serialized buffer (avoiding struct padding issues)
    static uint16_t computeChecksumFromBuffer(const uint8_t* buffer, size_t length) {
        if (length < 8) return 0;
        
        // Create temporary buffer without checksum field for CRC calculation
        // Copy bytes 0-6 (before checksum at bytes 7-8) and bytes 9 onwards
        uint8_t* temp_buffer = new uint8_t[length - 2];
        
        // Bytes 0-6 (before checksum)
        memcpy(temp_buffer, buffer, 7);
        
        // Skip bytes 7-8 (checksum field)
        
        // Bytes 9 to end (after checksum: rest of header + payload)
        if (length > 9) {
            memcpy(temp_buffer + 7, buffer + 9, length - 9);
        }
        
        uint16_t crc = computeCRC16(temp_buffer, length - 2);
        delete[] temp_buffer;
        
        return crc;
    }

    static void serializePacket(const BasicProtocolPacket& packet, uint8_t* buffer, size_t& length) {
        buffer[0] = packet.version_flags;
        buffer[1] = packet.msg_type;
        buffer[2] = (packet.source_addr >> 8) & 0xFF;
        buffer[3] = packet.source_addr & 0xFF;
        buffer[4] = (packet.dest_addr >> 8) & 0xFF;
        buffer[5] = packet.dest_addr & 0xFF;
        buffer[6] = packet.payload_length;
        buffer[7] = 0;  // Placeholder for checksum (high byte)
        buffer[8] = 0;  // Placeholder for checksum (low byte)
        buffer[9] = (packet.sequence_number >> 8) & 0xFF;
        buffer[10] = packet.sequence_number & 0xFF;
        buffer[11] = packet.ttl;
        buffer[12] = packet.priority_flags;
        buffer[13] = (packet.fragment_id >> 8) & 0xFF;
        buffer[14] = packet.fragment_id & 0xFF;
        buffer[15] = (packet.timestamp >> 24) & 0xFF;  // 32-bit timestamp
        buffer[16] = (packet.timestamp >> 16) & 0xFF;
        buffer[17] = (packet.timestamp >> 8) & 0xFF;
        buffer[18] = packet.timestamp & 0xFF;

        if (packet.payload_length > 0) {
            memcpy(buffer + HEADER_SIZE, packet.payload, packet.payload_length);
        }

        length = HEADER_SIZE + packet.payload_length;
        
        // Compute CRC-16 checksum from serialized buffer
        uint16_t crc = computeChecksumFromBuffer(buffer, length);
        buffer[7] = (crc >> 8) & 0xFF;  // High byte
        buffer[8] = crc & 0xFF;         // Low byte
    }

    static bool deserializePacket(const uint8_t* buffer, size_t length, BasicProtocolPacket& packet) {
        if (length < HEADER_SIZE) {
            return false;
        }

        packet.version_flags = buffer[0];
        packet.msg_type = buffer[1];
        packet.source_addr = (buffer[2] << 8) | buffer[3];
        packet.dest_addr = (buffer[4] << 8) | buffer[5];
        packet.payload_length = buffer[6];
        uint16_t received_checksum = (buffer[7] << 8) | buffer[8];  // 16-bit checksum

        packet.sequence_number = (buffer[9] << 8) | buffer[10];
        packet.ttl = buffer[11];
        packet.priority_flags = buffer[12];
        packet.fragment_id = (buffer[13] << 8) | buffer[14];
        packet.timestamp = ((uint32_t)buffer[15] << 24) | ((uint32_t)buffer[16] << 16) | 
                          ((uint32_t)buffer[17] << 8) | buffer[18];  // 32-bit timestamp

        if (length < HEADER_SIZE + packet.payload_length) {
            return false;
        }

        if (packet.payload_length > 0) {
            memcpy(packet.payload, buffer + HEADER_SIZE, packet.payload_length);
        }

        // Verify CRC-16 checksum from buffer (not struct, to avoid padding issues)
        uint16_t computed_checksum = computeChecksumFromBuffer(buffer, length);
        if (computed_checksum != received_checksum) {
            return false; // Checksum verification failed
        }

        packet.checksum = received_checksum; // Store the verified checksum

        return true;
    }

#if !defined(ESP_PLATFORM) && !defined(ARDUINO)
    // C++ std::vector overloads for router use
    static void serializePacket(const BasicProtocolPacket& packet, std::vector<uint8_t>& buffer) {
        buffer.resize(HEADER_SIZE + packet.payload_length);
        size_t length;
        serializePacket(packet, buffer.data(), length);
    }

    static bool deserializePacket(const std::vector<uint8_t>& buffer, BasicProtocolPacket& packet) {
        return deserializePacket(buffer.data(), buffer.size(), packet);
    }
#endif
};

#endif // PACKET_UTILS_H