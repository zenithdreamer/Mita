#ifndef MITA_ROUTER_INFRASTRUCTURE_DHCP_SERVER_HPP
#define MITA_ROUTER_INFRASTRUCTURE_DHCP_SERVER_HPP

#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <unistd.h>

namespace mita
{
    namespace core
    {
        class RouterConfig;
        class Logger;
    }
}

namespace mita
{
    namespace infrastructure
    {

        /**
         * DHCP Server Manager
         * Manages DHCP server using dnsmasq for the WiFi access point
         */
        class DHCPServerManager
        {
        public:
            explicit DHCPServerManager(const std::shared_ptr<core::RouterConfig> &config);
            ~DHCPServerManager();

            // DHCP server lifecycle
            bool setup_dhcp_server();
            bool teardown_dhcp_server();
            bool is_running() const { return running_; }

            // Status and monitoring
            bool verify_dhcp_server() const;
            std::string get_status() const;

        private:
            // Configuration management
            bool create_config_file();
            bool remove_config_file();

            // Interface detection
            std::string detect_wifi_interface() const;

            // Process management
            bool start_dnsmasq_process();
            bool stop_dnsmasq_process();
            void stop_all_dnsmasq_processes();

            // Verification
            bool check_dhcp_process() const;

            // Utilities
            bool run_command(const std::vector<std::string> &command, std::string *output = nullptr) const;

            // Configuration
            std::shared_ptr<core::RouterConfig> config_;
            std::shared_ptr<core::Logger> logger_;

            // DHCP settings
            std::string interface_;
            std::string server_ip_;
            std::string dhcp_start_;
            std::string dhcp_end_;

            // File paths
            std::filesystem::path config_dir_;
            std::filesystem::path config_file_;
            std::string pid_file_;

            // State
            bool running_ = false;
            pid_t dnsmasq_pid_ = -1;
        };

    } // namespace infrastructure
} // namespace mita

#endif // MITA_ROUTER_INFRASTRUCTURE_DHCP_SERVER_HPP