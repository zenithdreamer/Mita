#include "../include/transport/wifi_transport.h"
#include "../../shared/protocol/packet_utils.h"
#include "../../shared/config/mita_config.h"
#include "../../shared/transport/transport_constants.h"
#include <esp_log.h>
#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_netif.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

static const char *TAG = "WIFI_TRANSPORT";

static EventGroupHandle_t wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;

WiFiTransport::WiFiTransport()
    : raw_socket(-1), connected(false), shared_secret("Mita_password"), router_ip(0), local_ip(0)
{
}

WiFiTransport::WiFiTransport(const std::string &shared_secret)
    : raw_socket(-1), connected(false), shared_secret(shared_secret), router_ip(0), local_ip(0)
{
}

WiFiTransport::~WiFiTransport()
{
    disconnect();
}

bool WiFiTransport::connect()
{
    ESP_LOGI(TAG, "WiFiTransport: Attempting connection...");

    // Initialize WiFi if not already done
    static bool wifi_initialized = false;
    if (!wifi_initialized) {
        ESP_ERROR_CHECK(esp_netif_init());
        ESP_ERROR_CHECK(esp_event_loop_create_default());
        esp_netif_create_default_wifi_sta();
        
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        ESP_ERROR_CHECK(esp_wifi_init(&cfg));
        
        wifi_event_group = xEventGroupCreate();
        
        ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
            [](void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
                if (event_id == WIFI_EVENT_STA_START) {
                    // Don't auto-connect - let connect() handle it after scanning
                    ESP_LOGI(TAG, "WiFi STA started");
                } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
                    xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
                    ESP_LOGI(TAG, "Disconnected from AP");
                }
            }, nullptr));
            
        ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
            [](void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
                ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
                ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
                xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
            }, nullptr));
        
        wifi_initialized = true;
    }

    if (!scanForRouter()) {
        ESP_LOGE(TAG, "WiFiTransport: Router AP not found");
        return false;
    }

    if (!connectToAP()) {
        ESP_LOGE(TAG, "WiFiTransport: Failed to connect to AP");
        return false;
    }

    if (!createRawSocket()) {
        ESP_LOGE(TAG, "WiFiTransport: Failed to create raw socket");
        esp_wifi_disconnect();
        return false;
    }

    connected = true;
    ESP_LOGI(TAG, "WiFiTransport: Connection successful");
    return true;
}

void WiFiTransport::disconnect()
{
    if (raw_socket >= 0) {
        close(raw_socket);
        raw_socket = -1;
    }
    esp_wifi_disconnect();
    connected = false;
    ESP_LOGI(TAG, "WiFiTransport: Disconnected");
}

bool WiFiTransport::isConnected() const
{
    wifi_ap_record_t ap_info;
    return (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) && (raw_socket >= 0);
}

bool WiFiTransport::sendPacket(const BasicProtocolPacket &packet)
{
    if (!isConnected()) {
        return false;
    }

    uint8_t buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t length;
    PacketUtils::serializePacket(packet, buffer, length);

    return sendRawPacket(buffer, length, router_ip);
}

bool WiFiTransport::receivePacket(BasicProtocolPacket &packet, unsigned long timeout_ms)
{
    if (!isConnected()) {
        ESP_LOGW(TAG, "WiFiTransport: receivePacket called but not connected");
        return false;
    }

    uint8_t buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t received = 0;
    uint32_t source_ip;

    if (receiveRawPacket(buffer, received, source_ip, timeout_ms)) {
        if (received >= HEADER_SIZE) {
            return PacketUtils::deserializePacket(buffer, received, packet);
        }
    }

    return false;
}

TransportType WiFiTransport::getType() const
{
    return TRANSPORT_WIFI;
}

std::string WiFiTransport::getConnectionInfo() const
{
    if (!connected) {
        return "WiFi: Disconnected";
    }

    esp_netif_ip_info_t ip_info;
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
        
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            return std::string("WiFi: ") + ip_str + " (RSSI: " + 
                   std::to_string(ap_info.rssi) + " dBm)";
        }
        return std::string("WiFi: ") + ip_str;
    }

    return "WiFi: Connected";
}

int WiFiTransport::getSignalStrength() const
{
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
        return ap_info.rssi;
    }
    return -100;
}

bool WiFiTransport::scanForRouter()
{
    ESP_LOGI(TAG, "WiFiTransport: Scanning for router AP...");

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    
    // Give WiFi sufficient time to fully initialize before scanning
    vTaskDelay(pdMS_TO_TICKS(500));

    wifi_scan_config_t scan_config = {};
    scan_config.ssid = nullptr;
    scan_config.bssid = nullptr;
    scan_config.channel = 0;
    scan_config.show_hidden = true;
    scan_config.scan_type = WIFI_SCAN_TYPE_ACTIVE;

    esp_err_t err = esp_wifi_scan_start(&scan_config, true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WiFi scan failed: %s", esp_err_to_name(err));
        return false;
    }

    uint16_t ap_count = 0;
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    
    ESP_LOGI(TAG, "WiFiTransport: Found %d networks", ap_count);

    if (ap_count == 0) {
        return false;
    }

    wifi_ap_record_t *ap_list = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * ap_count);
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_count, ap_list));

    std::string patterns[] = {
        MITA_DEFAULT_ROUTER_ID,
        std::string(MITA_NETWORK_SSID)
    };

    bool found = false;
    for (int i = 0; i < ap_count; i++) {
        std::string ssid((char*)ap_list[i].ssid);
        ESP_LOGI(TAG, "  [%d] SSID: %s RSSI: %d dBm", i, ssid.c_str(), ap_list[i].rssi);

        for (int p = 0; p < 2; p++) {
            if (ssid.find(patterns[p]) != std::string::npos) {
                ESP_LOGI(TAG, "WiFiTransport: Found router AP: %s", ssid.c_str());
                discovered_ssid = ssid;
                found = true;
                break;
            }
        }
        if (found) break;
    }

    free(ap_list);
    return found;
}

bool WiFiTransport::connectToAP()
{
    if (discovered_ssid.empty()) {
        return false;
    }

    ESP_LOGI(TAG, "WiFiTransport: Connecting to %s", discovered_ssid.c_str());

    wifi_config_t wifi_config = {};
    strncpy((char*)wifi_config.sta.ssid, discovered_ssid.c_str(), sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char*)wifi_config.sta.password, shared_secret.c_str(), sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_connect());

    // Wait for connection
    EventBits_t bits = xEventGroupWaitBits(wifi_event_group,
            WIFI_CONNECTED_BIT,
            pdFALSE,
            pdFALSE,
            pdMS_TO_TICKS(10000));

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to AP");
        
        // Get IP info
        esp_netif_ip_info_t ip_info;
        esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
            router_ip = ip_info.gw.addr;
            local_ip = ip_info.ip.addr;
            ESP_LOGI(TAG, "Router IP: " IPSTR, IP2STR(&ip_info.gw));
            ESP_LOGI(TAG, "Local IP: " IPSTR, IP2STR(&ip_info.ip));
        }
        return true;
    }

    ESP_LOGE(TAG, "Failed to connect to AP");
    return false;
}

bool WiFiTransport::createRawSocket()
{
    // Create raw IP socket with custom protocol 253
    // ESP-IDF's lwIP will automatically add IP headers with the specified protocol
    raw_socket = socket(AF_INET, SOCK_RAW, MITA_IP_PROTOCOL);
    if (raw_socket < 0) {
        ESP_LOGE(TAG, "Failed to create raw socket: %d", errno);
        return false;
    }

    ESP_LOGI(TAG, "Raw socket created for protocol %d", MITA_IP_PROTOCOL);

    // Bind socket to receive packets on this interface
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;  // Receive on any address
    bind_addr.sin_port = 0;  // Not used for raw sockets
    
    if (bind(raw_socket, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind raw socket: %d", errno);
        close(raw_socket);
        raw_socket = -1;
        return false;
    }
    
    ESP_LOGI(TAG, "Raw socket bound to INADDR_ANY");

    // Set socket to non-blocking
    int flags = fcntl(raw_socket, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(raw_socket, F_SETFL, flags | O_NONBLOCK);
    }

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(raw_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ESP_LOGI(TAG, "Raw socket created successfully (protocol %d)", MITA_IP_PROTOCOL);
    return true;
}

bool WiFiTransport::sendRawPacket(const uint8_t *data, size_t length, uint32_t dest_ip)
{
    if (raw_socket < 0 || !connected) {
        ESP_LOGE(TAG, "Socket not ready");
        return false;
    }

    // When using socket(AF_INET, SOCK_RAW, protocol), lwIP will automatically
    // construct the IP header with the specified protocol number
    // We just send the payload and specify the destination
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = dest_ip;

    ssize_t sent = sendto(raw_socket, data, length, 0,
                         (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (sent < 0) {
        ESP_LOGE(TAG, "Send failed: %d (%s)", errno, strerror(errno));
        return false;
    }

    // Only log packet details at debug level
    if (length >= 2) {
        ESP_LOGD(TAG, "Sent %d bytes, type=0x%02X", sent, data[1]);
    }
    return sent == (ssize_t)length;
}

bool WiFiTransport::receiveRawPacket(uint8_t *buffer, size_t &length,
                                    uint32_t &source_ip, unsigned long timeout_ms)
{
    if (raw_socket < 0) {
        ESP_LOGE(TAG, "receiveRawPacket: socket not initialized");
        return false;
    }

    // Set timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(raw_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Only log for longer timeouts (not the frequent 10ms polls)
    if (timeout_ms >= 100) {
        ESP_LOGD(TAG, "Waiting for packet (timeout: %lu ms)...", timeout_ms);
    }

    unsigned long start_time = esp_timer_get_time() / 1000;  // Convert to ms
    int packet_count = 0;
    
    while ((esp_timer_get_time() / 1000 - start_time) < timeout_ms) {
        uint8_t recv_buf[2048]; // Buffer for IP header + payload
        struct sockaddr_in source_addr;
        socklen_t addr_len = sizeof(source_addr);

        ssize_t received = recvfrom(raw_socket, recv_buf, sizeof(recv_buf), 0,
                                   (struct sockaddr*)&source_addr, &addr_len);

        if (received > 0) {
            packet_count++;
            
            // Parse IP header
            uint8_t version = (recv_buf[0] >> 4) & 0x0F;
            uint8_t ihl = (recv_buf[0] & 0x0F) * 4;
            uint8_t protocol = recv_buf[9];
            
            ESP_LOGD(TAG, "Packet #%d: size=%d, protocol=%d", packet_count, received, protocol);
            
            // Check if it's our protocol (253)
            if (protocol == MITA_IP_PROTOCOL && version == 4) {
                // Copy payload (skip IP header)
                size_t payload_len = received - ihl;
                memcpy(buffer, recv_buf + ihl, payload_len);
                length = payload_len;
                source_ip = source_addr.sin_addr.s_addr;
                
                ESP_LOGD(TAG, "Received MITA packet: %d bytes, type=0x%02X",
                         payload_len, buffer[1]);
                return true;
            }
        }
        else if (received < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ESP_LOGE(TAG, "recvfrom error: %d (%s)", errno, strerror(errno));
                break;
            }
            // Timeout, try again
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }

    // Only log timeout warnings for longer waits (important packets)
    if (timeout_ms >= 100 && packet_count > 0) {
        ESP_LOGW(TAG, "Timeout after %lu ms, received %d non-MITA packets", 
                 timeout_ms, packet_count);
    }
    return false;
}
