#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include "protocol_types.h"
#include <string.h>

class PacketUtils {
public:
    static void serializePacket(const ProtocolPacket& packet, uint8_t* buffer, size_t& length) {
        buffer[0] = packet.version_flags;
        buffer[1] = packet.msg_type;
        buffer[2] = (packet.source_addr >> 8) & 0xFF;
        buffer[3] = packet.source_addr & 0xFF;
        buffer[4] = (packet.dest_addr >> 8) & 0xFF;
        buffer[5] = packet.dest_addr & 0xFF;
        buffer[6] = packet.payload_length;
        buffer[7] = packet.reserved;

        if (packet.payload_length > 0) {
            memcpy(buffer + HEADER_SIZE, packet.payload, packet.payload_length);
        }

        length = HEADER_SIZE + packet.payload_length;
    }

    static bool deserializePacket(const uint8_t* buffer, size_t length, ProtocolPacket& packet) {
        if (length < HEADER_SIZE) {
            return false;
        }

        packet.version_flags = buffer[0];
        packet.msg_type = buffer[1];
        packet.source_addr = (buffer[2] << 8) | buffer[3];
        packet.dest_addr = (buffer[4] << 8) | buffer[5];
        packet.payload_length = buffer[6];
        packet.reserved = buffer[7];

        if (length < HEADER_SIZE + packet.payload_length) {
            return false;
        }

        if (packet.payload_length > 0) {
            memcpy(packet.payload, buffer + HEADER_SIZE, packet.payload_length);
        }

        return true;
    }
};

#endif // PACKET_UTILS_H