#ifndef MITA_BLE_ADVERTISER_HPP
#define MITA_BLE_ADVERTISER_HPP

#include <string>
#include <memory>
#include <atomic>

namespace mita {
namespace transports {
namespace ble {

/**
 * BLE Advertiser using HCI commands
 * Advertises the router as "MITA-ROUTER" so ESP32 clients can discover it
 */
class BLEAdvertiser {
public:
    BLEAdvertiser(const std::string& device_name = "MITA-ROUTER");
    ~BLEAdvertiser();

    // Start advertising
    bool start();
    
    // Stop advertising
    void stop();
    
    // Check if advertising
    bool is_advertising() const { return advertising_.load(); }

private:
    std::string device_name_;
    int hci_socket_;
    std::atomic<bool> advertising_;

    // Helper functions
    bool open_hci_socket();
    void close_hci_socket();
    bool set_advertising_parameters();
    bool set_advertising_data();
    bool set_scan_response_data();
    bool enable_advertising(bool enable);
};

} // namespace ble
} // namespace transports
} // namespace mita

#endif // MITA_BLE_ADVERTISER_HPP
