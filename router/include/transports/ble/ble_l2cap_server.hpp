#ifndef MITA_BLE_L2CAP_SERVER_HPP
#define MITA_BLE_L2CAP_SERVER_HPP

#include <string>
#include <thread>
#include <vector>
#include <atomic>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>

namespace mita {
namespace transports {
namespace ble {

// L2CAP CoC PSM for MITA protocol
constexpr uint16_t MITA_L2CAP_PSM = 0x0081;
constexpr int MITA_L2CAP_MTU = 512;

// Callback for received data: (client_fd, device_addr, data, length)
using DataReceivedCallback = std::function<void(int, const std::string&, const uint8_t*, size_t)>;

// Callback for client connect/disconnect: (client_fd, device_addr)
using ClientEventCallback = std::function<void(int, const std::string&)>;

class BLEL2CAPServer {
public:
    BLEL2CAPServer();
    ~BLEL2CAPServer();

    // Start the L2CAP CoC server
    bool start();
    
    // Stop the server and disconnect all clients
    void stop();
    
    // Check if server is running
    bool is_running() const { return running_.load(); }
    
    // Send data to a specific client
    bool send_to_client(int client_fd, const uint8_t* data, size_t length);
    
    // Broadcast data to all connected clients
    int broadcast(const uint8_t* data, size_t length);
    
    // Get connection info
    std::string get_connection_info() const;
    
    // Set callbacks
    void set_data_received_callback(DataReceivedCallback callback) {
        data_received_callback_ = callback;
    }
    
    void set_client_connected_callback(ClientEventCallback callback) {
        client_connected_callback_ = callback;
    }
    
    void set_client_disconnected_callback(ClientEventCallback callback) {
        client_disconnected_callback_ = callback;
    }

private:
    int server_socket_;
    std::atomic<bool> running_;
    std::thread accept_thread_;
    std::vector<std::thread> client_threads_;
    
    // Map of client_fd -> device address
    std::unordered_map<int, std::string> client_map_;
    std::mutex client_map_mutex_;
    
    // Callbacks
    DataReceivedCallback data_received_callback_;
    ClientEventCallback client_connected_callback_;
    ClientEventCallback client_disconnected_callback_;
    
    // Worker functions
    void accept_loop();
    void client_worker(int client_fd, bdaddr_t peer_addr);
    
    // Helper functions
    std::string bdaddr_to_string(const bdaddr_t& addr);
    bool setup_socket();
    void cleanup();
};

} // namespace ble
} // namespace transports
} // namespace mita

#endif // MITA_BLE_L2CAP_SERVER_HPP
