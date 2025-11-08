#include "transports/ble/ble_l2cap_server.hpp"
#include "core/logger.hpp"
#include <iostream>
#include <sstream>
#include <csignal>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <errno.h>

namespace mita {
namespace transports {
namespace ble {

static auto logger = core::get_logger("BLE_L2CAP_Server");

BLEL2CAPServer::BLEL2CAPServer()
    : server_socket_(-1),
      running_(false)
{
    logger->info("BLE L2CAP CoC Server created");
}

BLEL2CAPServer::~BLEL2CAPServer()
{
    stop();
    logger->info("BLE L2CAP CoC Server destroyed");
}

bool BLEL2CAPServer::start()
{
    if (running_.load()) {
        logger->warning("Server already running");
        return true;
    }

    std::stringstream ss;
    ss << "Starting BLE L2CAP CoC server on PSM 0x" << std::hex << MITA_L2CAP_PSM;
    logger->info(ss.str());

    if (!setup_socket()) {
        logger->error("Failed to setup server socket");
        return false;
    }

    running_.store(true);
    
    // Start accept thread
    accept_thread_ = std::thread(&BLEL2CAPServer::accept_loop, this);
    
    logger->info("BLE L2CAP CoC server started successfully");
    return true;
}

void BLEL2CAPServer::stop()
{
    if (!running_.load()) {
        return;
    }

    logger->info("Stopping BLE L2CAP CoC server...");
    running_.store(false);

    // Close all client sockets first to unblock recv() calls
    {
        std::lock_guard<std::mutex> lock(client_map_mutex_);
        for (const auto& pair : client_map_) {
            shutdown(pair.first, SHUT_RDWR);
            close(pair.first);
        }
    }

    // Close server socket to unblock accept()
    if (server_socket_ >= 0) {
        shutdown(server_socket_, SHUT_RDWR);
        close(server_socket_);
        server_socket_ = -1;
    }

    // Wait for accept thread
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }

    // Wait for all client threads
    for (auto& t : client_threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    client_threads_.clear();

    cleanup();
    logger->info("BLE L2CAP CoC server stopped");
}

bool BLEL2CAPServer::send_to_client(int client_fd, const uint8_t* data, size_t length)
{
    if (client_fd < 0) {
        logger->error("Invalid client fd");
        return false;
    }

    ssize_t sent = send(client_fd, data, length, 0);
    if (sent < 0) {
        logger->error("Failed to send to client " + std::to_string(client_fd) + 
                     ": " + std::string(strerror(errno)));
        return false;
    }

    logger->debug("Sent " + std::to_string(sent) + " bytes to client " + 
                 std::to_string(client_fd));
    return true;
}

int BLEL2CAPServer::broadcast(const uint8_t* data, size_t length)
{
    std::lock_guard<std::mutex> lock(client_map_mutex_);
    int count = 0;

    for (const auto& pair : client_map_) {
        if (send_to_client(pair.first, data, length)) {
            count++;
        }
    }

    logger->debug("Broadcast to " + std::to_string(count) + " clients");
    return count;
}

std::string BLEL2CAPServer::get_connection_info() const
{
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(client_map_mutex_));
    return "BLE L2CAP CoC Server: " + std::to_string(client_map_.size()) + 
           " client(s) connected on PSM 0x" + std::to_string(MITA_L2CAP_PSM);
}

bool BLEL2CAPServer::setup_socket()
{
    // Create L2CAP socket
    server_socket_ = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (server_socket_ < 0) {
        logger->error("Failed to create socket: " + std::string(strerror(errno)));
        return false;
    }

    // Allow socket reuse
    int opt = 1;
    if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        logger->warning("Failed to set SO_REUSEADDR: " + std::string(strerror(errno)));
    }

    // Bind to LE address + PSM
    struct sockaddr_l2 local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.l2_family = AF_BLUETOOTH;
    local_addr.l2_bdaddr = {{0, 0, 0, 0, 0, 0}}; // BDADDR_ANY
    local_addr.l2_bdaddr_type = BDADDR_LE_PUBLIC; // LE Public address
    local_addr.l2_psm = htobs(MITA_L2CAP_PSM);

    if (bind(server_socket_, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        logger->error("Failed to bind socket: " + std::string(strerror(errno)));
        close(server_socket_);
        server_socket_ = -1;
        return false;
    }

    // Set L2CAP options (MTU)
    struct l2cap_options opts;
    socklen_t optlen = sizeof(opts);
    
    if (getsockopt(server_socket_, SOL_L2CAP, L2CAP_OPTIONS, &opts, &optlen) == 0) {
        opts.omtu = MITA_L2CAP_MTU;
        opts.imtu = MITA_L2CAP_MTU;
        
        if (setsockopt(server_socket_, SOL_L2CAP, L2CAP_OPTIONS, &opts, optlen) < 0) {
            logger->warning("Failed to set L2CAP options: " + std::string(strerror(errno)));
        } else {
            logger->info("L2CAP MTU set to " + std::to_string(MITA_L2CAP_MTU));
        }
    }

    // Set security level to low (no authentication/encryption required for testing)
    struct bt_security sec;
    memset(&sec, 0, sizeof(sec));
    sec.level = BT_SECURITY_LOW; // No authentication required
    
    if (setsockopt(server_socket_, SOL_BLUETOOTH, BT_SECURITY, &sec, sizeof(sec)) < 0) {
        logger->warning("Failed to set security level: " + std::string(strerror(errno)));
    } else {
        logger->info("Security level set to LOW (no auth required)");
    }

    // Listen
    if (listen(server_socket_, 5) < 0) {
        logger->error("Failed to listen: " + std::string(strerror(errno)));
        close(server_socket_);
        server_socket_ = -1;
        return false;
    }

    std::stringstream ss2;
    ss2 << "Server socket listening on LE PSM 0x" << std::hex << MITA_L2CAP_PSM;
    logger->info(ss2.str());
    return true;
}

void BLEL2CAPServer::accept_loop()
{
    logger->info("Accept loop started");

    while (running_.load()) {
        // Use select() with timeout for responsive shutdown
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_socket_, &readfds);
        
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000; // 200ms timeout
        
        int ret = select(server_socket_ + 1, &readfds, nullptr, nullptr, &tv);
        
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (!running_.load()) {
                break;
            }
            logger->error("Select failed: " + std::string(strerror(errno)));
            break;
        }
        
        if (ret == 0) {
            // Timeout - check running flag and loop
            continue;
        }
        
        // Socket is ready for accept
        struct sockaddr_l2 remote_addr;
        socklen_t addr_len = sizeof(remote_addr);
        
        int client_fd = accept(server_socket_, (struct sockaddr*)&remote_addr, &addr_len);
        
        if (client_fd < 0) {
            if (!running_.load()) {
                break;
            }
            
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            
            logger->error("Accept failed: " + std::string(strerror(errno)));
            break;
        }

        std::string addr_str = bdaddr_to_string(remote_addr.l2_bdaddr);
        logger->info("Accepted connection from " + addr_str + ", fd=" + 
                    std::to_string(client_fd));

        // Add to client map
        {
            std::lock_guard<std::mutex> lock(client_map_mutex_);
            client_map_[client_fd] = addr_str;
        }

        // Call connected callback
        if (client_connected_callback_) {
            client_connected_callback_(client_fd, addr_str);
        }

        // Spawn client worker thread
        client_threads_.emplace_back(&BLEL2CAPServer::client_worker, this, 
                                     client_fd, remote_addr.l2_bdaddr);
    }

    logger->info("Accept loop exited");
}

void BLEL2CAPServer::client_worker(int client_fd, bdaddr_t peer_addr)
{
    std::string addr_str = bdaddr_to_string(peer_addr);
    logger->info("Client worker started for " + addr_str);

    uint8_t buffer[2048];

    while (running_.load()) {
        ssize_t n = recv(client_fd, buffer, sizeof(buffer), 0);
        
        if (n <= 0) {
            if (n < 0) {
                logger->error("Recv error from " + addr_str + ": " + 
                             std::string(strerror(errno)));
            } else {
                logger->info("Client " + addr_str + " disconnected");
            }
            break;
        }

        logger->debug("Received " + std::to_string(n) + " bytes from " + addr_str);

        // Call data received callback
        if (data_received_callback_) {
            data_received_callback_(client_fd, addr_str, buffer, n);
        }

        // Echo back (for testing/debugging)
        // send(client_fd, buffer, n, 0);
    }

    // Cleanup - close socket if not already closed
    if (client_fd >= 0) {
        close(client_fd);
    }
    
    // Remove from client map
    {
        std::lock_guard<std::mutex> lock(client_map_mutex_);
        client_map_.erase(client_fd);
    }

    // Call disconnected callback
    if (client_disconnected_callback_) {
        client_disconnected_callback_(client_fd, addr_str);
    }

    logger->info("Client worker for " + addr_str + " exited");
}

std::string BLEL2CAPServer::bdaddr_to_string(const bdaddr_t& addr)
{
    char str[18];
    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x",
             addr.b[5], addr.b[4], addr.b[3], addr.b[2], addr.b[1], addr.b[0]);
    return std::string(str);
}

void BLEL2CAPServer::cleanup()
{
    std::lock_guard<std::mutex> lock(client_map_mutex_);
    
    // Close all client connections
    for (const auto& pair : client_map_) {
        close(pair.first);
    }
    
    client_map_.clear();
}

} // namespace ble
} // namespace transports
} // namespace mita
