#include "core/config.hpp"
#include <fstream>
#include <stdexcept>
#include <iostream>

namespace mita
{
    namespace core
    {

        // WiFiConfig implementation
        void WiFiConfig::from_json(const nlohmann::json &j)
        {
            if (j.contains("enabled"))
                enabled = j["enabled"];
            if (j.contains("server_host"))
                server_host = j["server_host"];
            if (j.contains("server_port"))
                server_port = j["server_port"];
            if (j.contains("channel"))
                channel = j["channel"];
            if (j.contains("max_connections"))
                max_connections = j["max_connections"];
            if (j.contains("ap_timeout"))
                ap_timeout = j["ap_timeout"];
        }

        nlohmann::json WiFiConfig::to_json() const
        {
            return nlohmann::json{
                {"enabled", enabled},
                {"server_host", server_host},
                {"server_port", server_port},
                {"channel", channel},
                {"max_connections", max_connections},
                {"ap_timeout", ap_timeout}};
        }

        // BLEConfig implementation
        void BLEConfig::from_json(const nlohmann::json &j)
        {
            if (j.contains("enabled"))
                enabled = j["enabled"];
            if (j.contains("scan_interval"))
                scan_interval = j["scan_interval"];
            if (j.contains("scan_pause"))
                scan_pause = j["scan_pause"];
            if (j.contains("service_uuid"))
                service_uuid = j["service_uuid"];
            if (j.contains("characteristic_uuid"))
                characteristic_uuid = j["characteristic_uuid"];
            if (j.contains("device_name"))
                device_name = j["device_name"];
            if (j.contains("max_connections"))
                max_connections = j["max_connections"];
        }

        nlohmann::json BLEConfig::to_json() const
        {
            return nlohmann::json{
                {"enabled", enabled},
                {"scan_interval", scan_interval},
                {"scan_pause", scan_pause},
                {"service_uuid", service_uuid},
                {"characteristic_uuid", characteristic_uuid},
                {"device_name", device_name},
                {"max_connections", max_connections}};
        }

        // RoutingConfig implementation
        void RoutingConfig::from_json(const nlohmann::json &j)
        {
            if (j.contains("cleanup_interval"))
                cleanup_interval = j["cleanup_interval"];
            if (j.contains("device_timeout"))
                device_timeout = j["device_timeout"];
            if (j.contains("max_devices"))
                max_devices = j["max_devices"];
            if (j.contains("auto_assign_addresses"))
                auto_assign_addresses = j["auto_assign_addresses"];
        }

        nlohmann::json RoutingConfig::to_json() const
        {
            return nlohmann::json{
                {"cleanup_interval", cleanup_interval},
                {"device_timeout", device_timeout},
                {"max_devices", max_devices},
                {"auto_assign_addresses", auto_assign_addresses}};
        }

        // SecurityConfig implementation
        void SecurityConfig::from_json(const nlohmann::json &j)
        {
            if (j.contains("encryption_enabled"))
                encryption_enabled = j["encryption_enabled"];
            if (j.contains("handshake_timeout"))
                handshake_timeout = j["handshake_timeout"];
            if (j.contains("session_timeout"))
                session_timeout = j["session_timeout"];
            if (j.contains("max_handshake_attempts"))
                max_handshake_attempts = j["max_handshake_attempts"];
        }

        nlohmann::json SecurityConfig::to_json() const
        {
            return nlohmann::json{
                {"encryption_enabled", encryption_enabled},
                {"handshake_timeout", handshake_timeout},
                {"session_timeout", session_timeout},
                {"max_handshake_attempts", max_handshake_attempts}};
        }

        // LoggingConfig implementation
        void LoggingConfig::from_json(const nlohmann::json &j)
        {
            if (j.contains("status_interval"))
                status_interval = j["status_interval"];
            if (j.contains("log_level"))
                log_level = j["log_level"];
            if (j.contains("log_file") && !j["log_file"].is_null())
                log_file = j["log_file"];
        }

        nlohmann::json LoggingConfig::to_json() const
        {
            nlohmann::json j{
                {"status_interval", status_interval},
                {"log_level", log_level}};
            if (!log_file.empty())
            {
                j["log_file"] = log_file;
            }
            return j;
        }

        // DevelopmentConfig implementation
        void DevelopmentConfig::from_json(const nlohmann::json &j)
        {
            if (j.contains("skip_ap_setup"))
                skip_ap_setup = j["skip_ap_setup"];
            if (j.contains("debug_packets"))
                debug_packets = j["debug_packets"];
            if (j.contains("mock_interfaces"))
                mock_interfaces = j["mock_interfaces"];
        }

        nlohmann::json DevelopmentConfig::to_json() const
        {
            return nlohmann::json{
                {"skip_ap_setup", skip_ap_setup},
                {"debug_packets", debug_packets},
                {"mock_interfaces", mock_interfaces}};
        }

        // RouterConfig implementation
        RouterConfig::RouterConfig(const std::string &router_id, const std::string &shared_secret)
            : router_id(router_id), shared_secret(shared_secret)
        {
            apply_router_id_defaults();
        }

        std::unique_ptr<RouterConfig> RouterConfig::from_file(const std::string &config_path)
        {
            std::ifstream file(config_path);
            if (!file.is_open())
            {
                throw std::runtime_error("Configuration file not found: " + config_path);
            }

            nlohmann::json j;
            try
            {
                file >> j;
            }
            catch (const nlohmann::json::parse_error &e)
            {
                throw std::runtime_error("Invalid JSON in configuration file: " + std::string(e.what()));
            }

            return from_json(j);
        }

        std::unique_ptr<RouterConfig> RouterConfig::from_json(const nlohmann::json &j)
        {
            // Extract required fields
            if (!j.contains("router_id") || j["router_id"].empty())
            {
                throw std::invalid_argument("router_id is required");
            }
            if (!j.contains("shared_secret") || j["shared_secret"].empty())
            {
                throw std::invalid_argument("shared_secret is required");
            }

            auto config = std::make_unique<RouterConfig>(j["router_id"], j["shared_secret"]);

            // Load sub-configurations
            if (j.contains("wifi"))
            {
                config->wifi.from_json(j["wifi"]);
            }
            if (j.contains("ble"))
            {
                config->ble.from_json(j["ble"]);
            }
            if (j.contains("routing"))
            {
                config->routing.from_json(j["routing"]);
            }
            if (j.contains("security"))
            {
                config->security.from_json(j["security"]);
            }
            if (j.contains("logging"))
            {
                config->logging.from_json(j["logging"]);
            }
            if (j.contains("development"))
            {
                config->development.from_json(j["development"]);
            }

            config->apply_router_id_defaults();
            return config;
        }

        std::unique_ptr<RouterConfig> RouterConfig::create_default(const std::string &router_id,
                                                                   const std::string &shared_secret)
        {
            return std::make_unique<RouterConfig>(router_id, shared_secret);
        }

        nlohmann::json RouterConfig::to_json() const
        {
            return nlohmann::json{
                {"router_id", router_id},
                {"shared_secret", shared_secret},
                {"wifi", wifi.to_json()},
                {"ble", ble.to_json()},
                {"routing", routing.to_json()},
                {"security", security.to_json()},
                {"logging", logging.to_json()},
                {"development", development.to_json()}};
        }

        void RouterConfig::save_to_file(const std::string &config_path) const
        {
            std::ofstream file(config_path);
            if (!file.is_open())
            {
                throw std::runtime_error("Cannot open configuration file for writing: " + config_path);
            }

            file << to_json().dump(4);
        }

        bool RouterConfig::validate() const
        {
            // Validate router_id
            if (router_id.empty())
            {
                std::cerr << "Configuration validation error: router_id cannot be empty" << std::endl;
                return false;
            }

            // Validate shared_secret
            if (shared_secret.length() < 8)
            {
                std::cerr << "Configuration validation error: shared_secret must be at least 8 characters" << std::endl;
                return false;
            }

            // Validate WiFi config
            if (wifi.server_port < 1 || wifi.server_port > 65535)
            {
                std::cerr << "Configuration validation error: wifi.server_port must be between 1 and 65535" << std::endl;
                return false;
            }

            // Validate BLE config
            if (ble.scan_interval <= 0)
            {
                std::cerr << "Configuration validation error: ble.scan_interval must be positive" << std::endl;
                return false;
            }

            // Validate timeouts
            if (routing.device_timeout <= 0)
            {
                std::cerr << "Configuration validation error: routing.device_timeout must be positive" << std::endl;
                return false;
            }

            if (security.handshake_timeout <= 0)
            {
                std::cerr << "Configuration validation error: security.handshake_timeout must be positive" << std::endl;
                return false;
            }

            return true;
        }

        void RouterConfig::apply_router_id_defaults()
        {
            // Update BLE device name with router ID if it's the default
            if (ble.device_name == "Mita_Router")
            {
                ble.device_name = router_id + "_Router";
            }
        }

    } // namespace core
} // namespace mita