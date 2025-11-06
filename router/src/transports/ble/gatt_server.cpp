#include "transports/ble/gatt_server.hpp"
#include "core/logger.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <algorithm>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <poll.h>

namespace mita
{
    namespace transports
    {
        namespace ble
        {
            // ATT Protocol opcodes
            constexpr uint8_t ATT_OP_ERROR = 0x01;
            constexpr uint8_t ATT_OP_MTU_REQ = 0x02;
            constexpr uint8_t ATT_OP_MTU_RESP = 0x03;
            constexpr uint8_t ATT_OP_FIND_INFO_REQ = 0x04;
            constexpr uint8_t ATT_OP_FIND_INFO_RESP = 0x05;
            constexpr uint8_t ATT_OP_READ_BY_TYPE_REQ = 0x08;
            constexpr uint8_t ATT_OP_READ_BY_TYPE_RESP = 0x09;
            constexpr uint8_t ATT_OP_READ_REQ = 0x0A;
            constexpr uint8_t ATT_OP_READ_RESP = 0x0B;
            constexpr uint8_t ATT_OP_WRITE_REQ = 0x12;
            constexpr uint8_t ATT_OP_WRITE_RESP = 0x13;
            constexpr uint8_t ATT_OP_HANDLE_VAL_NOT = 0x1B;

            // ATT Error codes
            constexpr uint8_t ATT_ECODE_INVALID_HANDLE = 0x01;
            constexpr uint8_t ATT_ECODE_READ_NOT_PERM = 0x02;
            constexpr uint8_t ATT_ECODE_WRITE_NOT_PERM = 0x03;
            constexpr uint8_t ATT_ECODE_ATTR_NOT_FOUND = 0x0A;

            // L2CAP PSM for ATT
            constexpr uint16_t L2CAP_PSM_ATT = 31;

            GattServer::GattServer(const std::string &service_uuid,
                                   const std::string &char_uuid,
                                   std::function<void(const std::string &, const std::vector<uint8_t> &)> on_write,
                                   std::function<std::vector<uint8_t>(const std::string &)> on_read)
                : service_uuid_(service_uuid),
                  char_uuid_(char_uuid),
                  on_write_callback_(on_write),
                  on_read_callback_(on_read),
                  server_sock_(-1),
                  running_(false),
                  mtu_(23),              // Default ATT MTU
                  value_handle_(0x0010), // Characteristic value handle
                  logger_(core::get_logger("GattServer"))
            {
            }

            GattServer::~GattServer()
            {
                stop();
            }

            bool GattServer::start(const std::string &adapter_name)
            {
                if (logger_)
                    logger_->info("Starting L2CAP GATT server",
                                  core::LogContext{}
                                      .add("adapter", adapter_name)
                                      .add("service_uuid", service_uuid_)
                                      .add("char_uuid", char_uuid_));

                // Create L2CAP socket
                server_sock_ = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
                if (server_sock_ < 0)
                {
                    if (logger_)
                        logger_->error("Failed to create L2CAP socket", core::LogContext{}.add("error", strerror(errno)));
                    return false;
                }

                // Set socket to non-blocking
                int flags = fcntl(server_sock_, F_GETFL, 0);
                fcntl(server_sock_, F_SETFL, flags | O_NONBLOCK);

                // Bind to ATT PSM
                struct sockaddr_l2 addr = {0};
                addr.l2_family = AF_BLUETOOTH;
                addr.l2_psm = htobs(L2CAP_PSM_ATT);
                // Use BDADDR_ANY - bind to any local adapter
                bdaddr_t any_addr = {{0, 0, 0, 0, 0, 0}};
                memcpy(&addr.l2_bdaddr, &any_addr, sizeof(bdaddr_t));
                addr.l2_cid = 0;
                addr.l2_bdaddr_type = BDADDR_LE_PUBLIC;

                if (bind(server_sock_, (struct sockaddr *)&addr, sizeof(addr)) < 0)
                {
                    if (logger_)
                        logger_->error("Failed to bind L2CAP socket", core::LogContext{}.add("error", strerror(errno)));
                    close(server_sock_);
                    server_sock_ = -1;
                    return false;
                }

                // Listen for connections
                if (listen(server_sock_, 10) < 0)
                {
                    if (logger_)
                        logger_->error("Failed to listen on L2CAP socket", core::LogContext{}.add("error", strerror(errno)));
                    close(server_sock_);
                    server_sock_ = -1;
                    return false;
                }

                running_ = true;

                // Start accept thread
                accept_thread_ = std::thread(&GattServer::accept_loop, this);

                if (logger_)
                    logger_->info("GATT server started successfully - waiting for connections");

                return true;
            }

            void GattServer::stop()
            {
                if (!running_)
                    return;

                running_ = false;

                // Close server socket
                if (server_sock_ >= 0)
                {
                    close(server_sock_);
                    server_sock_ = -1;
                }

                // Close all client connections
                {
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    for (auto &pair : client_sockets_)
                    {
                        close(pair.second);
                    }
                    client_sockets_.clear();
                    connected_clients_.clear();
                }

                if (accept_thread_.joinable())
                {
                    accept_thread_.join();
                }

                if (logger_)
                    logger_->info("GATT server stopped");
            }

            void GattServer::accept_loop()
            {
                if (logger_)
                    logger_->debug("Accept thread started");

                while (running_)
                {
                    struct sockaddr_l2 client_addr = {0};
                    socklen_t addr_len = sizeof(client_addr);

                    int client_sock = accept(server_sock_, (struct sockaddr *)&client_addr, &addr_len);

                    if (client_sock < 0)
                    {
                        if (errno != EAGAIN && errno != EWOULDBLOCK)
                        {
                            if (logger_ && running_)
                                logger_->error("Accept failed", core::LogContext{}.add("error", strerror(errno)));
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        continue;
                    }

                    // Convert address to string
                    char addr_str[18];
                    ba2str(&client_addr.l2_bdaddr, addr_str);
                    std::string client_address(addr_str);

                    if (logger_)
                        logger_->info("New BLE client connected", core::LogContext{}.add("address", client_address));

                    // Store client socket
                    {
                        std::lock_guard<std::mutex> lock(clients_mutex_);
                        client_sockets_[client_address] = client_sock;
                        connected_clients_.push_back(client_address);
                    }

                    // Start handler thread for this client
                    std::thread(&GattServer::handle_client, this, client_sock, client_address).detach();
                }

                if (logger_)
                    logger_->debug("Accept thread stopped");
            }

            void GattServer::handle_client(int client_sock, const std::string &client_address)
            {
                if (logger_)
                    logger_->debug("Client handler started", core::LogContext{}.add("address", client_address));

                uint8_t buffer[512];

                while (running_)
                {
                    struct pollfd pfd;
                    pfd.fd = client_sock;
                    pfd.events = POLLIN;

                    int ret = poll(&pfd, 1, 1000);
                    if (ret < 0)
                        break;

                    if (ret == 0)
                        continue;

                    int len = recv(client_sock, buffer, sizeof(buffer), 0);
                    if (len <= 0)
                        break;

                    // Process ATT PDU
                    process_att_pdu(client_sock, client_address, buffer, len);
                }

                // Client disconnected
                if (logger_)
                    logger_->info("BLE client disconnected", core::LogContext{}.add("address", client_address));

                {
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    client_sockets_.erase(client_address);
                    auto it = std::find(connected_clients_.begin(), connected_clients_.end(), client_address);
                    if (it != connected_clients_.end())
                    {
                        connected_clients_.erase(it);
                    }
                }

                close(client_sock);
            }

            void GattServer::process_att_pdu(int client_sock, const std::string &client_address,
                                             const uint8_t *data, size_t len)
            {
                if (len < 1)
                    return;

                uint8_t opcode = data[0];
                uint8_t response[512];
                size_t response_len = 0;

                switch (opcode)
                {
                case ATT_OP_MTU_REQ:
                    if (len >= 3)
                    {
                        uint16_t client_mtu = data[1] | (data[2] << 8);
                        mtu_ = std::min(client_mtu, uint16_t(512));
                        response[0] = ATT_OP_MTU_RESP;
                        response[1] = mtu_ & 0xFF;
                        response[2] = (mtu_ >> 8) & 0xFF;
                        response_len = 3;

                        if (logger_)
                            logger_->debug("MTU exchange", core::LogContext{}.add("mtu", mtu_));
                    }
                    break;

                case ATT_OP_WRITE_REQ:
                    if (len >= 3)
                    {
                        uint16_t handle = data[1] | (data[2] << 8);
                        std::vector<uint8_t> value(data + 3, data + len);

                        if (logger_)
                            logger_->debug("Write request",
                                           core::LogContext{}
                                               .add("handle", handle)
                                               .add("len", value.size()));

                        // Call write callback
                        if (on_write_callback_)
                        {
                            on_write_callback_(client_address, value);
                        }

                        // Send write response
                        response[0] = ATT_OP_WRITE_RESP;
                        response_len = 1;
                    }
                    break;

                case ATT_OP_READ_REQ:
                    if (len >= 3)
                    {
                        uint16_t handle = data[1] | (data[2] << 8);

                        if (logger_)
                            logger_->debug("Read request", core::LogContext{}.add("handle", handle));

                        // Call read callback
                        std::vector<uint8_t> value;
                        if (on_read_callback_)
                        {
                            value = on_read_callback_(client_address);
                        }

                        // Send read response
                        response[0] = ATT_OP_READ_RESP;
                        size_t copy_len = std::min(value.size(), size_t(mtu_ - 1));
                        memcpy(response + 1, value.data(), copy_len);
                        response_len = 1 + copy_len;
                    }
                    break;

                default:
                    if (logger_)
                        logger_->debug("Unhandled ATT opcode",
                                       core::LogContext{}.add("opcode", static_cast<int>(opcode)));
                    break;
                }

                // Send response
                if (response_len > 0)
                {
                    send(client_sock, response, response_len, 0);
                }
            }

            bool GattServer::notify_characteristic(const std::string &client_address, const std::vector<uint8_t> &data)
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);

                auto it = client_sockets_.find(client_address);
                if (it == client_sockets_.end())
                    return false;

                // Build notification PDU
                uint8_t pdu[512];
                pdu[0] = ATT_OP_HANDLE_VAL_NOT;
                pdu[1] = value_handle_ & 0xFF;
                pdu[2] = (value_handle_ >> 8) & 0xFF;

                size_t copy_len = std::min(data.size(), size_t(mtu_ - 3));
                memcpy(pdu + 3, data.data(), copy_len);

                int ret = send(it->second, pdu, 3 + copy_len, 0);

                if (logger_)
                    logger_->debug("Sent notification",
                                   core::LogContext{}
                                       .add("client", client_address)
                                       .add("size", copy_len)
                                       .add("result", ret));

                return ret > 0;
            }

            std::vector<std::string> GattServer::get_connected_clients() const
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                return connected_clients_;
            }

        } // namespace ble
    } // namespace transports
} // namespace mita
