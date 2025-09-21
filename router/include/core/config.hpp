#ifndef MITA_ROUTER_CONFIG_HPP
#define MITA_ROUTER_CONFIG_HPP

#include <string>
#include <memory>
#include <nlohmann/json.hpp>

namespace mita
{
    namespace core
    {

        /**
         * WiFi transport configuration
         */
        struct WiFiConfig
        {
            bool enabled = true;
            std::string server_host = "192.168.50.1";
            int server_port = 8000;
            int channel = 6;
            int max_connections = 10;
            int ap_timeout = 30;

            void from_json(const nlohmann::json &j);
            nlohmann::json to_json() const;
        };

        /**
         * BLE transport configuration
         */
        struct BLEConfig
        {
            bool enabled = true;
            double scan_interval = 5.0;
            double scan_pause = 2.0;
            std::string service_uuid = "12345678-1234-1234-1234-123456789abc";
            std::string characteristic_uuid = "12345678-1234-1234-1234-123456789abd";
            std::string device_name = "Mita_Router";
            int max_connections = 7;

            void from_json(const nlohmann::json &j);
            nlohmann::json to_json() const;
        };

        /**
         * Routing configuration
         */
        struct RoutingConfig
        {
            int cleanup_interval = 60;
            int device_timeout = 300;
            int max_devices = 100;
            bool auto_assign_addresses = true;

            void from_json(const nlohmann::json &j);
            nlohmann::json to_json() const;
        };

        /**
         * Security configuration
         */
        struct SecurityConfig
        {
            bool encryption_enabled = true;
            int handshake_timeout = 30;
            int session_timeout = 3600;
            int max_handshake_attempts = 3;

            void from_json(const nlohmann::json &j);
            nlohmann::json to_json() const;
        };

        /**
         * Logging configuration
         */
        struct LoggingConfig
        {
            int status_interval = 30;
            std::string log_level = "INFO";
            std::string log_file; // Empty means console output

            void from_json(const nlohmann::json &j);
            nlohmann::json to_json() const;
        };

        /**
         * Development and testing configuration
         */
        struct DevelopmentConfig
        {
            bool skip_ap_setup = false;
            bool debug_packets = false;
            bool mock_interfaces = false;

            void from_json(const nlohmann::json &j);
            nlohmann::json to_json() const;
        };

        /**
         * Complete router configuration
         */
        class RouterConfig
        {
        public:
            // Core configuration
            std::string router_id;
            std::string shared_secret;

            // Sub-configurations
            WiFiConfig wifi;
            BLEConfig ble;
            RoutingConfig routing;
            SecurityConfig security;
            LoggingConfig logging;
            DevelopmentConfig development;

        public:
            RouterConfig() = default;
            RouterConfig(const std::string &router_id, const std::string &shared_secret);

            // Factory methods
            static std::unique_ptr<RouterConfig> from_file(const std::string &config_path);
            static std::unique_ptr<RouterConfig> from_json(const nlohmann::json &j);
            static std::unique_ptr<RouterConfig> create_default(const std::string &router_id,
                                                                const std::string &shared_secret);

            // Serialization
            nlohmann::json to_json() const;
            void save_to_file(const std::string &config_path) const;

            // Validation
            bool validate() const;

        private:
            void apply_router_id_defaults();
        };

    } // namespace core
} // namespace mita

#endif // MITA_ROUTER_CONFIG_HPP