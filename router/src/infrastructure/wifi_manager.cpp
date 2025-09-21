/**
 * WiFi Access Point Manager Implementation
 * Handles creation and management of WiFi access points using NetworkManager
 */

#include "infrastructure/wifi_manager.hpp"
#include "infrastructure/dhcp_server.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"

#include <cstdlib>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <regex>
#include <chrono>
#include <thread>

namespace mita
{
    namespace infrastructure
    {

        WiFiAccessPointManager::WiFiAccessPointManager(const std::shared_ptr<core::RouterConfig> &config)
            : config_(config), logger_(core::get_logger("WiFiAccessPointManager"))
        {

            // Connection settings
            connection_name_ = "Mita-AP-" + config->router_id;
            ssid_ = config->router_id;
            password_ = config->shared_secret;

            // Network settings
            ip_address_ = config->wifi.server_host;
            subnet_ = "192.168.50.0/24";
            interface_ = detect_wifi_interface();

            // Initialize DHCP server manager
            dhcp_server_ = std::make_unique<DHCPServerManager>(config);

            logger_->info("WiFi AP Manager initialized",
                          core::LogContext()
                              .add("connection_name", connection_name_)
                              .add("ssid", ssid_)
                              .add("interface", interface_));
        }

        WiFiAccessPointManager::~WiFiAccessPointManager()
        {
            if (running_)
            {
                teardown_hotspot();
            }
        }

        bool WiFiAccessPointManager::setup_hotspot()
        {
            logger_->info("Setting up WiFi Access Point...");

            // Check if running as root
            if (geteuid() != 0)
            {
                logger_->error("Root privileges required for WiFi AP setup");
                return false;
            }

            try
            {
                // Remove existing connection if it exists
                remove_existing_connection();

                // Create new hotspot connection first
                if (!create_hotspot_connection())
                {
                    logger_->error("Failed to create hotspot connection");
                    return false;
                }

                // Wait a moment for connection to be ready
                std::this_thread::sleep_for(std::chrono::seconds(2));

                // Activate the connection to create the interface
                if (!activate_connection())
                {
                    logger_->error("Failed to activate connection");
                    remove_existing_connection();
                    return false;
                }

                // Wait for interface to be fully up
                std::this_thread::sleep_for(std::chrono::seconds(3));

                // Now setup DHCP server after WiFi interface is created
                logger_->info("Setting up DHCP server...");
                if (!dhcp_server_->setup_dhcp_server())
                {
                    logger_->error("Failed to setup DHCP server");
                    // Cleanup and return error
                    deactivate_connection();
                    remove_existing_connection();
                    return false;
                }

                // Verify the connection is working
                if (verify_hotspot())
                {
                    running_ = true;
                    logger_->info("WiFi Access Point setup successful",
                                  core::LogContext()
                                      .add("ssid", ssid_)
                                      .add("ip_address", ip_address_)
                                      .add("dhcp_enabled", true));
                    return true;
                }
                else
                {
                    logger_->error("WiFi Access Point verification failed");
                    dhcp_server_->teardown_dhcp_server();
                    deactivate_connection();
                    remove_existing_connection();
                    return false;
                }
            }
            catch (const std::exception &e)
            {
                logger_->error("Error setting up WiFi hotspot", core::LogContext().add("error", e.what()));
                // Cleanup on exception
                try
                {
                    dhcp_server_->teardown_dhcp_server();
                    deactivate_connection();
                    remove_existing_connection();
                }
                catch (const std::exception &)
                {
                    // Ignore cleanup errors
                }
                return false;
            }
        }

        bool WiFiAccessPointManager::teardown_hotspot()
        {
            if (!running_)
            {
                return true;
            }

            logger_->info("Tearing down WiFi Access Point...");

            try
            {
                // Stop DHCP server first
                if (dhcp_server_)
                {
                    dhcp_server_->teardown_dhcp_server();
                }

                // Deactivate connection
                deactivate_connection();

                // Remove connection
                remove_existing_connection();

                running_ = false;
                logger_->info("WiFi Access Point teardown completed");
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error tearing down WiFi hotspot", core::LogContext().add("error", e.what()));
                return false;
            }
        }

        void WiFiAccessPointManager::show_security_settings() const
        {
            logger_->info("WiFi Access Point Security Settings",
                          core::LogContext()
                              .add("ssid", ssid_)
                              .add("security", "WPA2-PSK")
                              .add("password_length", std::to_string(password_.length())));
        }

        bool WiFiAccessPointManager::verify_hotspot() const
        {
            // Check if connection is active
            if (!verify_connection_active())
            {
                logger_->warning("Connection not active");
                return false;
            }

            // Check if interface has the correct IP
            if (!verify_interface_has_ip())
            {
                logger_->warning("Interface does not have expected IP address");
                return false;
            }

            // Check if DHCP server is running
            if (!dhcp_server_ || !dhcp_server_->is_running())
            {
                logger_->warning("DHCP server is not running");
                return false;
            }

            logger_->debug("WiFi Access Point verification successful");
            return true;
        }

        std::string WiFiAccessPointManager::get_status() const
        {
            std::ostringstream status;
            status << "WiFi Access Point Status:\n";
            status << "  Running: " << (running_ ? "Yes" : "No") << "\n";
            status << "  SSID: " << ssid_ << "\n";
            status << "  Interface: " << interface_ << "\n";
            status << "  IP Address: " << ip_address_ << "\n";
            status << "  Connection: " << connection_name_ << "\n";
            if (dhcp_server_)
            {
                status << "  DHCP Server: " << (dhcp_server_->is_running() ? "Running" : "Stopped");
            }
            return status.str();
        }

        std::string WiFiAccessPointManager::detect_wifi_interface() const
        {
            std::string output;
            if (!run_nmcli_command({"device", "status"}, &output))
            {
                logger_->warning("Failed to get device status from NetworkManager");
                return "wlan0"; // Fallback
            }

            // Parse output to find WiFi device
            std::istringstream stream(output);
            std::string line;
            std::regex wifi_regex(R"((\w+)\s+wifi\s+)");

            while (std::getline(stream, line))
            {
                std::smatch match;
                if (std::regex_search(line, match, wifi_regex))
                {
                    std::string interface = match[1].str();
                    logger_->debug("Detected WiFi interface", core::LogContext().add("interface", interface));
                    return interface;
                }
            }

            logger_->warning("No WiFi interface detected, using fallback");
            return "wlan0";
        }

        bool WiFiAccessPointManager::check_interface_available(const std::string &interface) const
        {
            std::string output;
            if (!run_nmcli_command({"device", "show", interface}, &output))
            {
                return false;
            }
            return !output.empty();
        }

        bool WiFiAccessPointManager::remove_existing_connection()
        {
            logger_->debug("Removing existing connection", core::LogContext().add("connection", connection_name_));

            // First deactivate if active
            deactivate_connection();

            // Then delete the connection (ignore errors if it doesn't exist)
            run_nmcli_command({"connection", "delete", connection_name_});

            return true;
        }

        bool WiFiAccessPointManager::create_hotspot_connection()
        {
            logger_->info("Creating hotspot connection", core::LogContext().add("connection", connection_name_));

            std::vector<std::string> command = {
                "connection", "add",
                "type", "wifi",
                "ifname", interface_,
                "con-name", connection_name_,
                "autoconnect", "no",
                "wifi.mode", "ap",
                "wifi.ssid", ssid_,
                "wifi.band", "bg",
                "wifi.channel", std::to_string(config_->wifi.channel),
                "wifi-sec.key-mgmt", "wpa-psk",
                "wifi-sec.psk", password_,
                "wifi-sec.proto", "rsn",           // Force WPA2 (RSN)
                "wifi-sec.pairwise", "ccmp",       // Use AES-CCMP encryption
                "wifi-sec.group", "ccmp",          // Use AES-CCMP for group
                "wifi-sec.wps-method", "disabled", // Disable WPS
                "wifi-sec.pmf", "default",         // Protected Management Frames
                "ipv4.method", "manual",           // Manual IP (handle DHCP separately)
                "ipv4.address", ip_address_ + "/24",
                "ipv4.gateway", ip_address_,
                "ipv4.dns", ip_address_};

            // Log the full command for debugging, might be useful if AP creation fails
            std::ostringstream cmd_stream;
            cmd_stream << "nmcli";
            for (const auto &arg : command)
            {
                cmd_stream << " " << arg;
            }
            logger_->debug("Creating hotspot connection", core::LogContext().add("command", cmd_stream.str()));
            logger_->info("Configuring WiFi AP with WPA2-PSK + AES-CCMP security (WPS disabled)");

            std::string output;
            if (!run_nmcli_command(command, &output))
            {
                logger_->error("Failed to create hotspot connection", core::LogContext().add("output", output));
                return false;
            }

            logger_->debug("Hotspot connection created successfully");
            return true;
        }

        bool WiFiAccessPointManager::activate_connection()
        {
            logger_->info("Activating hotspot connection", core::LogContext().add("connection", connection_name_));

            std::string output;
            if (!run_nmcli_command({"connection", "up", connection_name_}, &output))
            {
                logger_->error("Failed to activate hotspot connection", core::LogContext().add("output", output));
                return false;
            }

            logger_->debug("Hotspot connection activated successfully");
            return true;
        }

        bool WiFiAccessPointManager::deactivate_connection()
        {
            logger_->debug("Deactivating hotspot connection", core::LogContext().add("connection", connection_name_));

            // Try to deactivate the connection (ignore errors)
            run_nmcli_command({"connection", "down", connection_name_});

            return true;
        }

        bool WiFiAccessPointManager::run_nmcli_command(const std::vector<std::string> &args, std::string *output) const
        {
            std::ostringstream cmd;
            cmd << "nmcli";
            for (const auto &arg : args)
            {
                cmd << " \"" << arg << "\"";
            }
            cmd << " 2>/dev/null";

            FILE *pipe = popen(cmd.str().c_str(), "r");
            if (!pipe)
            {
                return false;
            }

            if (output)
            {
                output->clear();
                char buffer[256];
                while (fgets(buffer, sizeof(buffer), pipe))
                {
                    *output += buffer;
                }
            }

            int result = pclose(pipe);
            return WIFEXITED(result) && WEXITSTATUS(result) == 0;
        }

        bool WiFiAccessPointManager::verify_connection_active() const
        {
            std::string output;
            if (!run_nmcli_command({"connection", "show", "--active"}, &output))
            {
                return false;
            }

            return output.find(connection_name_) != std::string::npos;
        }

        bool WiFiAccessPointManager::verify_interface_has_ip() const
        {
            std::string output;
            if (!run_nmcli_command({"device", "show", interface_}, &output))
            {
                return false;
            }

            return output.find(ip_address_) != std::string::npos;
        }

    } // namespace infrastructure
} // namespace mita