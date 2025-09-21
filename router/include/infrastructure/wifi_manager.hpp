#ifndef MITA_ROUTER_INFRASTRUCTURE_WIFI_MANAGER_HPP
#define MITA_ROUTER_INFRASTRUCTURE_WIFI_MANAGER_HPP

#include <string>
#include <memory>
#include <vector>

namespace mita
{
    namespace core
    {
        class RouterConfig;
        class Logger;
    }
    namespace infrastructure
    {
        class DHCPServerManager;
    }
}

namespace mita
{
    namespace infrastructure
    {

        /**
         * WiFi Access Point Manager
         * Handles creation and management of WiFi access points using NetworkManager
         */
        class WiFiAccessPointManager
        {
        public:
            explicit WiFiAccessPointManager(const std::shared_ptr<core::RouterConfig> &config);
            ~WiFiAccessPointManager();

            // Access Point lifecycle
            bool setup_hotspot();
            bool teardown_hotspot();
            bool is_running() const { return running_; }

            // Security and monitoring
            void show_security_settings() const;
            bool verify_hotspot() const;
            std::string get_status() const;

        private:
            // Connection management
            bool remove_existing_connection();
            bool create_hotspot_connection();
            bool activate_connection();
            bool deactivate_connection();

            // Interface detection and management
            std::string detect_wifi_interface() const;
            bool check_interface_available(const std::string &interface) const;

            // NetworkManager D-Bus operations
            bool run_nmcli_command(const std::vector<std::string> &args, std::string *output = nullptr) const;

            // Verification
            bool verify_connection_active() const;
            bool verify_interface_has_ip() const;

            // Configuration
            std::shared_ptr<core::RouterConfig> config_;
            std::shared_ptr<core::Logger> logger_;

            // Connection settings
            std::string connection_name_;
            std::string ssid_;
            std::string password_;

            // Network settings
            std::string ip_address_;
            std::string subnet_;
            std::string interface_;

            // DHCP server manager
            std::unique_ptr<DHCPServerManager> dhcp_server_;

            // State
            bool running_ = false;
        };

    } // namespace infrastructure
} // namespace mita

#endif // MITA_ROUTER_INFRASTRUCTURE_WIFI_MANAGER_HPP