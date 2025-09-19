#ifndef TRANSPORT_INTERFACE_H
#define TRANSPORT_INTERFACE_H

#include <Arduino.h>
#include "protocol_types.h"

class ITransport {
public:
    virtual ~ITransport() = default;

    virtual bool connect() = 0;
    virtual void disconnect() = 0;
    virtual bool isConnected() const = 0;

    virtual bool sendPacket(const ProtocolPacket& packet) = 0;
    virtual bool receivePacket(ProtocolPacket& packet, unsigned long timeout_ms = 1000) = 0;

    virtual TransportType getType() const = 0;
    virtual String getConnectionInfo() const = 0;
};

#endif // TRANSPORT_INTERFACE_H