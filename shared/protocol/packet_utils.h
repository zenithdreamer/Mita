#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include "protocol_types.h"
#include <string.h>

class PacketUtils {
public:
    static uint8_t computeChecksum(const BasicProtocolPacket& packet) {
        uint32_t sum = 0;

        sum += packet.version_flags;
        sum += packet.msg_type;
        sum += (packet.source_addr >> 8) & 0xFF;
        sum += packet.source_addr & 0xFF;
        sum += (packet.dest_addr >> 8) & 0xFF;
        sum += packet.dest_addr & 0xFF;
        sum += packet.payload_length;

        // Add payload bytes
        for (uint8_t i = 0; i < packet.payload_length; i++) {
            sum += packet.payload[i];
        }

        // Return one's complement
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
        buffer[7] = computeChecksum(packet);

        if (packet.payload_length > 0) {
            memcpy(buffer + HEADER_SIZE, packet.payload, packet.payload_length);
        }

        length = HEADER_SIZE + packet.payload_length;
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

        if (length < HEADER_SIZE + packet.payload_length) {
            return false;
        }

        if (packet.payload_length > 0) {
            memcpy(packet.payload, buffer + HEADER_SIZE, packet.payload_length);
        }

        // Verify checksum
        uint8_t computed_checksum = computeChecksum(packet);
        if (computed_checksum != received_checksum) {
            return false; // Checksum verification failed
        }

        packet.checksum = received_checksum; // Store the verified checksum

        return true;
    }
};

#endif // PACKET_UTILS_H