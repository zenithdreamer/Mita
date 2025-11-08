#ifndef BLE_TRANSPORT_H
#define BLE_TRANSPORT_H

#include <string>
#include <cstring>
#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "host/ble_gap.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "../../shared/protocol/transport_interface.h"
#include "../../shared/protocol/protocol_types.h"
#include "../../shared/transport/transport_constants.h"

// L2CAP CoC parameters for MITA protocol
#define MITA_L2CAP_PSM 0x0081
#define MITA_L2CAP_MTU 512

// Forward declarations
class BLETransport;

// BLE Transport - Client Mode (connects TO router) using NimBLE L2CAP CoC
class BLETransport : public ITransport {
private:
    std::string device_id;
    std::string router_id;
    
    uint16_t conn_handle;
    struct ble_l2cap_chan *coc_chan;  // L2CAP CoC channel
    
    bool ble_connected;
    bool scanning;
    bool coc_connected;
    
    // Packet buffering
    uint8_t packet_buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t packet_length;
    bool packet_available;
    
    // Target router address
    ble_addr_t router_addr;
    bool router_found;

    // Client mode methods
    bool scanForRouter();
    bool connectToRouter();
    bool openCoCChannel();
    bool queueReceiveBuffer();
    
    // Static instance pointer for callbacks
    static BLETransport* instance;
    
    // NimBLE callbacks (static)
    static int gap_event_handler(struct ble_gap_event *event, void *arg);
    static int coc_event_handler(struct ble_l2cap_event *event, void *arg);

public:
    BLETransport(const std::string& device_id, const std::string& router_id);
    ~BLETransport() override;

    bool connect() override;
    void disconnect() override;
    bool isConnected() const override;

    bool sendPacket(const BasicProtocolPacket& packet) override;
    bool receivePacket(BasicProtocolPacket& packet, unsigned long timeout_ms = 1000) override;

    TransportType getType() const override;
    std::string getConnectionInfo() const override;

    // BLE callback handlers
    void onGapConnect();
    void onGapDisconnect();
    void onCoCConnected(struct ble_l2cap_chan *chan);
    void onCoCDisconnected(struct ble_l2cap_chan *chan);
    void onCoCDataReceived(struct os_mbuf *sdu);
    void onDeviceFound(const struct ble_gap_disc_desc *disc);
};

#endif // BLE_TRANSPORT_H
