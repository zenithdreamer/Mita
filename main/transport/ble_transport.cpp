#include "../include/transport/ble_transport.h"
#include "../../shared/protocol/packet_utils.h"
#include "../../shared/config/mita_config.h"
#include <esp_log.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include "nvs_flash.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_l2cap.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

static const char *TAG = "BLE_TRANSPORT";

// Static instance pointer for callbacks
BLETransport* BLETransport::instance = nullptr;

BLETransport::BLETransport(const std::string& device_id, const std::string& router_id)
    : device_id(device_id), router_id(router_id),
      conn_handle(BLE_HS_CONN_HANDLE_NONE), coc_chan(nullptr),
      ble_connected(false), scanning(false), coc_connected(false),
      packet_length(0), packet_available(false), router_found(false)
{
    instance = this;
    memset(&router_addr, 0, sizeof(router_addr));
}

BLETransport::~BLETransport()
{
    disconnect();
    if (instance == this) {
        instance = nullptr;
    }
}

bool BLETransport::connect()
{
    ESP_LOGI(TAG, "BLETransport: Initializing NimBLE for L2CAP CoC...");
    
    // Initialize NVS (only once globally)
    static bool nvs_initialized = false;
    if (!nvs_initialized) {
        esp_err_t ret = nvs_flash_init();
        if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
            ESP_ERROR_CHECK(nvs_flash_erase());
            ret = nvs_flash_init();
        }
        ESP_ERROR_CHECK(ret);
        nvs_initialized = true;
    }

    // Initialize NimBLE (only once globally)
    static bool nimble_initialized = false;
    if (!nimble_initialized) {
        esp_err_t ret = nimble_port_init();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "NimBLE port init failed: %d", ret);
            return false;
        }
        
        // Configure host
        ble_hs_cfg.reset_cb = [](int reason) {
            ESP_LOGW(TAG, "BLE host reset, reason=%d", reason);
        };
        
        ble_hs_cfg.sync_cb = []() {
            ESP_LOGI(TAG, "BLE host synced");
            if (BLETransport::instance) {
                // Start scanning once host is synced
                BLETransport::instance->scanForRouter();
            }
        };

        // Start NimBLE host task
        nimble_port_freertos_init([](void*) {
            nimble_port_run();
        });

        nimble_initialized = true;
        ESP_LOGI(TAG, "Waiting for BLE stack initialization...");
        vTaskDelay(pdMS_TO_TICKS(1000));
    } else {
        // Already initialized, just start scanning
        ESP_LOGI(TAG, "NimBLE already initialized, starting scan...");
        vTaskDelay(pdMS_TO_TICKS(100));
        scanForRouter();
    }

    // Wait for connection
    int timeout = 300; // 30 seconds
    while (!coc_connected && timeout-- > 0) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    if (!coc_connected) {
        ESP_LOGE(TAG, "Failed to establish CoC connection");
        disconnect(); // Clean up properly
        return false;
    }

    ESP_LOGI(TAG, "Connected to router via L2CAP CoC");
    return true;
}

bool BLETransport::scanForRouter()
{
    ESP_LOGI(TAG, "======================================");
    ESP_LOGI(TAG, "Scanning for router '%s'...", router_id.c_str());
    ESP_LOGI(TAG, "======================================");
    
    router_found = false;
    scanning = true;

    struct ble_gap_disc_params disc_params = {};
    disc_params.itvl = 0x30;  // 30ms scan interval
    disc_params.window = 0x30; // 30ms scan window (continuous)
    disc_params.filter_policy = 0; // Accept all
    disc_params.limited = 0; // General discovery
    disc_params.passive = 0; // Active scanning (with scan requests)
    disc_params.filter_duplicates = 1; // Filter duplicates

    ESP_LOGI(TAG, "Scan parameters: interval=0x%04x, window=0x%04x, passive=%d",
             disc_params.itvl, disc_params.window, disc_params.passive);

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params,
                          gap_event_handler, nullptr);
    
    if (rc != 0) {
        ESP_LOGE(TAG, "Error initiating GAP discovery: rc=%d", rc);
        scanning = false;
        return false;
    }

    ESP_LOGI(TAG, "Scan started successfully - waiting for advertisements...");
    return true;
}

bool BLETransport::connectToRouter()
{
    if (!router_found) {
        ESP_LOGE(TAG, "Router not found, cannot connect");
        return false;
    }

    ESP_LOGI(TAG, "Connecting to router...");

    struct ble_gap_conn_params conn_params = {
        .scan_itvl = 0x50,
        .scan_window = 0x30,
        .itvl_min = 24,
        .itvl_max = 24,
        .latency = 0,
        .supervision_timeout = 400,
        .min_ce_len = 0,
        .max_ce_len = 0,
    };

    int rc = ble_gap_connect(BLE_OWN_ADDR_PUBLIC, &router_addr, 30000,
                            &conn_params, gap_event_handler, nullptr);
    
    if (rc != 0) {
        ESP_LOGE(TAG, "Error initiating connection: rc=%d", rc);
        return false;
    }

    ESP_LOGI(TAG, "Connection initiated");
    return true;
}

bool BLETransport::openCoCChannel()
{
    ESP_LOGI(TAG, "Opening L2CAP CoC channel to PSM 0x%04x...", MITA_L2CAP_PSM);
    
    if (conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        ESP_LOGE(TAG, "Not connected, cannot open CoC");
        return false;
    }

    // Allocate receive buffer for L2CAP CoC
    struct os_mbuf *sdu_rx = os_msys_get_pkthdr(MITA_L2CAP_MTU, 0);
    if (!sdu_rx) {
        ESP_LOGE(TAG, "Failed to allocate receive buffer");
        return false;
    }

    // Connect to remote PSM (client-side connection)
    int rc = ble_l2cap_connect(conn_handle, MITA_L2CAP_PSM, MITA_L2CAP_MTU, sdu_rx, 
                          coc_event_handler, nullptr);
    
    if (rc != 0) {
        ESP_LOGE(TAG, "Error opening L2CAP CoC channel: rc=%d", rc);
        os_mbuf_free_chain(sdu_rx);
        return false;
    }

    ESP_LOGI(TAG, "L2CAP CoC channel connection initiated");
    return true;
}

bool BLETransport::queueReceiveBuffer()
{
    if (coc_chan == nullptr) {
        ESP_LOGW(TAG, "Cannot queue CoC receive buffer: channel not ready");
        return false;
    }

    struct os_mbuf *sdu_rx = os_msys_get_pkthdr(MITA_L2CAP_MTU, 0);
    if (sdu_rx == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate CoC receive buffer");
        return false;
    }

    int rc = ble_l2cap_recv_ready(coc_chan, sdu_rx);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_l2cap_recv_ready failed: rc=%d", rc);
        os_mbuf_free_chain(sdu_rx);
        return false;
    }

    return true;
}

void BLETransport::disconnect()
{
    if (coc_chan != nullptr) {
        ble_l2cap_disconnect(coc_chan);
        coc_chan = nullptr;
    }
    
    if (conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        conn_handle = BLE_HS_CONN_HANDLE_NONE;
    }
    
    // Stop scanning if active
    if (scanning) {
        ble_gap_disc_cancel();
        scanning = false;
    }
    
    ble_connected = false;
    coc_connected = false;
    router_found = false;
    
    ESP_LOGI(TAG, "Disconnected");
}

bool BLETransport::isConnected() const
{
    return ble_connected && coc_connected;
}

bool BLETransport::sendPacket(const BasicProtocolPacket &packet)
{
    ESP_LOGI(TAG, "sendPacket called: msg_type=%d payload_len=%d", packet.msg_type, packet.payload_length);
    
    if (!isConnected()) {
        ESP_LOGW(TAG, "Cannot send - not connected");
        return false;
    }

    if (coc_chan == nullptr) {
        ESP_LOGE(TAG, "CoC channel is null");
        return false;
    }

    ESP_LOGI(TAG, "About to serialize packet...");
    
    // Use heap allocation instead of stack to avoid stack overflow
    uint8_t *buffer = (uint8_t *)malloc(HEADER_SIZE + MAX_PAYLOAD_SIZE);
    if (buffer == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate buffer");
        return false;
    }
    
    size_t length;
    PacketUtils::serializePacket(packet, buffer, length);

    ESP_LOGI(TAG, "Packet serialized, length=%zu", length);

    // Allocate mbuf and send via L2CAP CoC
    ESP_LOGI(TAG, "Allocating mbuf for %zu bytes...", length);
    struct os_mbuf *sdu = os_msys_get_pkthdr(length, 0);
    if (sdu == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate mbuf");
        free(buffer);
        return false;
    }
    ESP_LOGI(TAG, "Mbuf allocated successfully, sdu=%p", sdu);

    ESP_LOGI(TAG, "Appending %zu bytes to mbuf...", length);
    int rc = os_mbuf_append(sdu, buffer, length);
    
    ESP_LOGI(TAG, "Freeing buffer...");
    free(buffer);  // Free buffer after copying to mbuf
    
    if (rc != 0) {
        ESP_LOGE(TAG, "Failed to append data to mbuf: rc=%d", rc);
        os_mbuf_free_chain(sdu);
        return false;
    }
    ESP_LOGI(TAG, "Data appended to mbuf successfully");

    // Validate coc_chan before sending
    if (coc_chan == nullptr) {
        ESP_LOGE(TAG, "CoC channel became null before send!");
        os_mbuf_free_chain(sdu);
        return false;
    }

    // Verify channel is still connected
    if (!coc_connected || !ble_connected) {
        ESP_LOGE(TAG, "Connection lost before send!");
        os_mbuf_free_chain(sdu);
        return false;
    }

    ESP_LOGI(TAG, "Sending via L2CAP CoC, coc_chan=%p, conn_handle=%d...", coc_chan, conn_handle);
    
    // Critical section: The ble_l2cap_send call might be failing due to channel state
    // Try to send with error handling
    rc = ble_l2cap_send(coc_chan, sdu);
    if (rc != 0) {
        ESP_LOGE(TAG, "Error sending via L2CAP CoC: rc=%d (BLE_HS_EBUSY=%d, BLE_HS_EDONE=%d)", 
                 rc, BLE_HS_EBUSY, BLE_HS_EDONE);
        // Note: ble_l2cap_send takes ownership of sdu, don't free it here even on error
        return false;
    }

    ESP_LOGI(TAG, "Sent %zu bytes via CoC successfully", length);
    return true;
}

bool BLETransport::receivePacket(BasicProtocolPacket &packet, unsigned long timeout_ms)
{
    uint64_t start_time = esp_timer_get_time() / 1000;

    while ((esp_timer_get_time() / 1000 - start_time) < timeout_ms) {
        if (packet_available) {
            if (PacketUtils::deserializePacket(packet_buffer, packet_length, packet)) {
                packet_available = false;
                packet_length = 0;
                return true;
            } else {
                ESP_LOGW(TAG, "Failed to deserialize packet");
                packet_available = false;
                packet_length = 0;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    return false;
}

TransportType BLETransport::getType() const
{
    return TRANSPORT_BLE;
}

std::string BLETransport::getConnectionInfo() const
{
    if (!ble_connected) {
        return "BLE: Disconnected";
    }
    if (!coc_connected) {
        return "BLE: Connected (CoC pending)";
    }
    return "BLE: Connected via L2CAP CoC (PSM 0x" + std::to_string(MITA_L2CAP_PSM) + ")";
}

// Callback handlers
void BLETransport::onGapConnect()
{
    ble_connected = true;
    ESP_LOGI(TAG, "GAP connection established, handle=%u", conn_handle);
    
    // Open CoC channel after GAP connection
    vTaskDelay(pdMS_TO_TICKS(500)); // Small delay for stability
    openCoCChannel();
}

void BLETransport::onGapDisconnect()
{
    ble_connected = false;
    coc_connected = false;
    coc_chan = nullptr;
    ESP_LOGW(TAG, "GAP disconnected");
    
    // Restart scanning
    if (!scanning) {
        scanForRouter();
    }
}

void BLETransport::onCoCConnected(struct ble_l2cap_chan *chan)
{
    coc_connected = true;
    coc_chan = chan;
    ESP_LOGI(TAG, "L2CAP CoC channel connected!");
    
    // Queue initial receive buffer for the channel
    if (!queueReceiveBuffer()) {
        ESP_LOGE(TAG, "Failed to queue initial receive buffer");
    }
}

void BLETransport::onCoCDisconnected(struct ble_l2cap_chan *chan)
{
    coc_connected = false;
    coc_chan = nullptr;
    ESP_LOGW(TAG, "L2CAP CoC channel disconnected");
}

void BLETransport::onCoCDataReceived(struct os_mbuf *sdu)
{
    uint16_t len = OS_MBUF_PKTLEN(sdu);
    
    if (len <= sizeof(packet_buffer)) {
        int rc = os_mbuf_copydata(sdu, 0, len, packet_buffer);
        if (rc == 0) {
            packet_length = len;
            packet_available = true;
            ESP_LOGD(TAG, "Received %u bytes via CoC", len);
        } else {
            ESP_LOGE(TAG, "Failed to copy mbuf data: rc=%d", rc);
        }
    } else {
        ESP_LOGW(TAG, "Received packet too large (%u bytes)", len);
    }

    os_mbuf_free_chain(sdu);

    // Queue next receive buffer to continue receiving
    // Only queue if we successfully processed this packet
    if (!queueReceiveBuffer()) {
        ESP_LOGW(TAG, "Failed to queue next receive buffer");
        // Don't disconnect - just log warning, channel may still work
    }
}

void BLETransport::onDeviceFound(const struct ble_gap_disc_desc *disc)
{
    // Log raw discovery event
    char addr_str[18];
    sprintf(addr_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            disc->addr.val[5], disc->addr.val[4], disc->addr.val[3],
            disc->addr.val[2], disc->addr.val[1], disc->addr.val[0]);
    
    ESP_LOGI(TAG, "BLE device discovered: addr=%s, rssi=%d, addr_type=%d, adv_data_len=%d, rsp_data_len=%d",
             addr_str, disc->rssi, disc->addr.type, disc->length_data, 
             (disc->event_type & BLE_HCI_ADV_RPT_EVTYPE_SCAN_RSP) ? disc->length_data : 0);
    
    // Parse advertising data to find device name
    struct ble_hs_adv_fields fields_adv = {};
    struct ble_hs_adv_fields fields_rsp = {};
    
    // Parse advertising data
    int rc = ble_hs_adv_parse_fields(&fields_adv, disc->data, disc->length_data);
    if (rc != 0) {
        ESP_LOGW(TAG, "Failed to parse advertising fields: rc=%d", rc);
        return;
    }
    
    // Check for name in advertising data first
    const uint8_t *name_data = fields_adv.name;
    uint8_t name_len = fields_adv.name_len;
    bool is_complete = fields_adv.name_is_complete;
    
    // If event contains scan response data, check it too
    if (disc->event_type & BLE_HCI_ADV_RPT_EVTYPE_SCAN_RSP) {
        // This packet IS the scan response, check for complete name
        if (fields_adv.name != nullptr && fields_adv.name_len > 0) {
            name_data = fields_adv.name;
            name_len = fields_adv.name_len;
            is_complete = fields_adv.name_is_complete;
        }
    }
    
    if (name_data != nullptr && name_len > 0) {
        char name[33] = {0};
        size_t len = name_len > 32 ? 32 : name_len;
        memcpy(name, name_data, len);
        
        ESP_LOGI(TAG, "  Device name: '%s' (len=%d, complete=%d, looking for '%s')", 
                 name, name_len, is_complete, instance->router_id.c_str());
        
        // Match complete name OR shortened name prefix
        if (strcmp(name, instance->router_id.c_str()) == 0) {
            ESP_LOGI(TAG, "*** FOUND TARGET ROUTER (exact match): %s ***", name);
            memcpy(&instance->router_addr, &disc->addr, sizeof(instance->router_addr));
            instance->router_found = true;
            
            // Stop scanning and connect
            ble_gap_disc_cancel();
            instance->scanning = false;
            
            instance->connectToRouter();
        }
        // Also check if this is a shortened version of our target name
        else if (!is_complete && strncmp(name, instance->router_id.c_str(), name_len) == 0 && 
                 instance->router_id.length() > name_len) {
            ESP_LOGI(TAG, "*** FOUND TARGET ROUTER (shortened match): %s... ***", name);
            memcpy(&instance->router_addr, &disc->addr, sizeof(instance->router_addr));
            instance->router_found = true;
            
            // Stop scanning and connect
            ble_gap_disc_cancel();
            instance->scanning = false;
            
            instance->connectToRouter();
        }
    } else {
        ESP_LOGD(TAG, "  No device name in this packet");
    }
}

// Static callback implementations
int BLETransport::gap_event_handler(struct ble_gap_event *event, void *arg)
{
    if (!instance) return 0;

    switch (event->type) {
    case BLE_GAP_EVENT_DISC:
        instance->onDeviceFound(&event->disc);
        break;

    case BLE_GAP_EVENT_DISC_COMPLETE:
        ESP_LOGI(TAG, "Discovery complete, reason=%d", event->disc_complete.reason);
        instance->scanning = false;
        
        // Restart scanning if not connected
        if (!instance->router_found && !instance->ble_connected) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            instance->scanForRouter();
        }
        break;

    case BLE_GAP_EVENT_CONNECT:
        ESP_LOGI(TAG, "GAP EVENT_CONNECT received, status=%d", event->connect.status);
        if (event->connect.status == 0) {
            instance->conn_handle = event->connect.conn_handle;
            instance->onGapConnect();
        } else {
            ESP_LOGE(TAG, "GAP connection failed, status=%d", event->connect.status);
            instance->router_found = false;
            
            // Restart scanning
            if (!instance->scanning) {
                vTaskDelay(pdMS_TO_TICKS(1000));
                instance->scanForRouter();
            }
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGW(TAG, "GAP disconnect event, reason=%d", event->disconnect.reason);
        instance->conn_handle = BLE_HS_CONN_HANDLE_NONE;
        instance->onGapDisconnect();
        break;

    case BLE_GAP_EVENT_CONN_UPDATE:
        ESP_LOGI(TAG, "Connection updated");
        break;

    case BLE_GAP_EVENT_CONN_UPDATE_REQ:
        // Accept connection parameter update request
        return 0;

    case BLE_GAP_EVENT_MTU:
        ESP_LOGI(TAG, "MTU updated: %d", event->mtu.value);
        break;
    }

    return 0;
}

int BLETransport::coc_event_handler(struct ble_l2cap_event *event, void *arg)
{
    if (!instance) return 0;

    switch (event->type) {
    case BLE_L2CAP_EVENT_COC_CONNECTED:
        ESP_LOGI(TAG, "CoC event: Connected, status=%d", event->connect.status);
        if (event->connect.status == 0) {
            instance->onCoCConnected(event->connect.chan);
        } else {
            ESP_LOGE(TAG, "CoC connection failed, status=%d", event->connect.status);
        }
        break;

    case BLE_L2CAP_EVENT_COC_DISCONNECTED:
        ESP_LOGW(TAG, "CoC event: Disconnected");
        instance->onCoCDisconnected(event->disconnect.chan);
        break;

    case BLE_L2CAP_EVENT_COC_DATA_RECEIVED:
        instance->onCoCDataReceived(event->receive.sdu_rx);
        break;

    case BLE_L2CAP_EVENT_COC_TX_UNSTALLED:
        ESP_LOGD(TAG, "CoC event: TX unstalled");
        break;

    case BLE_L2CAP_EVENT_COC_ACCEPT:
        ESP_LOGI(TAG, "CoC event: Accept (incoming connection)");
        // We're a client, shouldn't receive this
        break;

    default:
        ESP_LOGW(TAG, "Unknown CoC event type: %d", event->type);
        break;
    }

    return 0;
}
