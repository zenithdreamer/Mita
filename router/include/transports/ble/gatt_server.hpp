#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <atomic>

namespace mita
{
    namespace core
    {
        class Logger;
    }

    namespace transports
    {
        namespace ble
        {
            /**
             * GATT Server using L2CAP sockets and ATT protocol
             * 
             * This is a working GATT server implementation that:
             * - Accepts multiple client connections simultaneously
             * - Handles ATT protocol directly (Read/Write/Notify)
             * - Works with standard ESP32 BLE clients
             * - No complex D-Bus API needed
             */
            class GattServer
            {
            public:
                GattServer(const std::string &service_uuid,
                          const std::string &char_uuid,
                          std::function<void(const std::string &, const std::vector<uint8_t> &)> on_write,
                          std::function<std::vector<uint8_t>(const std::string &)> on_read);

                ~GattServer();

                bool start(const std::string &adapter_name = "hci0");
                void stop();
                bool notify_characteristic(const std::string &client_address, const std::vector<uint8_t> &data);
                std::vector<std::string> get_connected_clients() const;
                bool is_running() const { return running_; }

            private:
                void accept_loop();
                void handle_client(int client_sock, const std::string &client_address);
                void process_att_pdu(int client_sock, const std::string &client_address,
                                    const uint8_t *data, size_t len);

                std::string service_uuid_;
                std::string char_uuid_;

                std::function<void(const std::string &, const std::vector<uint8_t> &)> on_write_callback_;
                std::function<std::vector<uint8_t>(const std::string &)> on_read_callback_;

                int server_sock_;
                std::thread accept_thread_;
                std::atomic<bool> running_;

                uint16_t mtu_;
                uint16_t value_handle_;

                std::unordered_map<std::string, int> client_sockets_;
                std::vector<std::string> connected_clients_;
                mutable std::mutex clients_mutex_;

                std::shared_ptr<core::Logger> logger_;
            };

        } // namespace ble
    }     // namespace transports
} // namespace mita
