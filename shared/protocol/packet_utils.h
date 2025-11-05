#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include "protocol_types.h"
#include <string.h>

class PacketUtils {
public:
    
    // Compute checksum from serialized buffer (avoiding struct padding issues)
    // Uses simple sum algorithm matching the router implementation
    static uint8_t computeChecksumFromBuffer(const uint8_t* buffer, size_t length) {
        uint32_t sum = 0;
        
        // Bytes 0-6 (before checksum)
        for (int i = 0; i < 7; i++) {
            sum += buffer[i];
        }
        
        // Skip byte 7 (checksum field)
        
        // Bytes 8 to end (after checksum: rest of header + payload)
        for (size_t i = 8; i < length; i++) {
            sum += buffer[i];
        }
        
        // Return 8-bit checksum (sum of all bytes modulo 256, then one's complement)
        return static_cast<uint8_t>(~sum);
    }
    
    // Legacy function kept for compatibility (but should not be used due to struct padding)
    static uint8_t computeChecksum(const BasicProtocolPacket& packet) {
        uint32_t sum = 0;
        
        // Process header fields (excluding checksum byte itself)
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&packet);
        
        // Bytes 0-6 (before checksum)
        for (int i = 0; i < 7; i++) {
            sum += bytes[i];
        }
        
        // Skip byte 7 (checksum field)
        
        // Bytes 8-15 (after checksum, before payload)
        for (int i = 8; i < 16; i++) {
            sum += bytes[i];
        }
        
        // Payload bytes
        for (uint8_t i = 0; i < packet.payload_length; i++) {
            sum += packet.payload[i];
        }
        
        // Return 8-bit checksum (sum of all bytes modulo 256, then one's complement)
        return static_cast<uint8_t>(~sum);
    }

    static void serializePacket(const BasicProtocolPacket& packet, uint8_t* buffer, size_t& length) {
        buffer[0] = packet.version_flags;
        buffer[1] = packet.msg_type;
        buffer[2] = (packet.source_addr >> 8) & 0xFF;
        buffer[3] = packet.source_addr & 0xFF;
        buffer[4] = (packet.dest_addr >> 8) & 0xFF;
        buffer[5] = packet.dest_addr & 0xFF;
        buffer[6] = packet.payload_length;
        buffer[7] = 0;  // Placeholder for checksum
        buffer[8] = (packet.sequence_number >> 8) & 0xFF;
        buffer[9] = packet.sequence_number & 0xFF;
        buffer[10] = packet.ttl;
        buffer[11] = packet.priority_flags;
        buffer[12] = (packet.fragment_id >> 8) & 0xFF;
        buffer[13] = packet.fragment_id & 0xFF;
        buffer[14] = (packet.timestamp >> 8) & 0xFF;
        buffer[15] = packet.timestamp & 0xFF;

        if (packet.payload_length > 0) {
            memcpy(buffer + HEADER_SIZE, packet.payload, packet.payload_length);
        }

        length = HEADER_SIZE + packet.payload_length;
        
        // Compute checksum from serialized buffer
        buffer[7] = computeChecksumFromBuffer(buffer, length);
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
        uint8_t received_checksum = buffer[7];

        packet.sequence_number = (buffer[8] << 8) | buffer[9];
        packet.ttl = buffer[10];
        packet.priority_flags = buffer[11];
        packet.fragment_id = (buffer[12] << 8) | buffer[13];
        packet.timestamp = (buffer[14] << 8) | buffer[15];

        if (length < HEADER_SIZE + packet.payload_length) {
            return false;
        }

        if (packet.payload_length > 0) {
            memcpy(packet.payload, buffer + HEADER_SIZE, packet.payload_length);
        }

        // Verify checksum from buffer (not struct, to avoid padding issues)
        uint8_t computed_checksum = computeChecksumFromBuffer(buffer, length);
        if (computed_checksum != received_checksum) {
            return false; // Checksum verification failed
        }

        packet.checksum = received_checksum; // Store the verified checksum

        return true;
    }
};

#endif // PACKET_UTILS_H