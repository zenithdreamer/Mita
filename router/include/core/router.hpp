#ifndef MITA_ROUTER_CORE_ROUTER_HPP
#define MITA_ROUTER_CORE_ROUTER_HPP

#include <memory>
#include <map>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>
#include <condition_variable>

// Forward declarations
namespace mita
{
    namespace core
    {
        class RouterConfig;
        class Logger;
        class TransportInterface;
    }
    namespace services
    {
        class RoutingService;
        class StatisticsService;
        class DeviceManagementService;
    }
    namespace infrastructure
    {
        class WiFiAccessPointManager;
    }
}

namespace mita
{
    namespace core
    {

        /**
         * Main Mita Router class
         * Orchestrates all router components and services
         */
        class MitaRouter
        {
        public:
            explicit MitaRouter(std::unique_ptr<RouterConfig> config);
            ~MitaRouter();

            // Router lifecycle
            bool start();
            void stop();
            bool is_running() const { return running_; }

            // Public API
            bool send_message(const std::string &device_id, const std::vector<uint8_t> &message);
            int broadcast_message(const std::vector<uint8_t> &message);
            std::map<std::string, std::map<std::string, std::string>> get_connected_devices();
            std::map<std::string, uint64_t> get_statistics();
            std::map<std::string, std::string> get_router_info();

        private:
            // Setup methods
            bool setup_wifi_transport();
            bool setup_ble_transport();
            void start_background_tasks();
            void run_main_loop();
            void run_status_monitor();

            // Maintenance
            void periodic_maintenance();
            void log_status();

            // Configuration and logging
            std::unique_ptr<RouterConfig> config_;
            std::shared_ptr<Logger> logger_;

            // Core services
            std::unique_ptr<services::RoutingService> routing_service_;
            std::unique_ptr<services::StatisticsService> statistics_service_;
            std::unique_ptr<services::DeviceManagementService> device_management_;

            // Transport layers
            std::map<std::string, std::unique_ptr<TransportInterface>> transports_;

            // WiFi Infrastructure
            std::unique_ptr<infrastructure::WiFiAccessPointManager> wifi_ap_manager_;

            // Threading
            std::atomic<bool> running_{false};
            std::unique_ptr<std::thread> main_loop_thread_;
            std::unique_ptr<std::thread> status_thread_;

            // Thread synchro for shutdown
            std::mutex shutdown_mutex_;
            std::condition_variable shutdown_cv_;

            // Router startup time
            std::chrono::steady_clock::time_point start_time_;
        };

    } // namespace core
} // namespace mita

#endif // MITA_ROUTER_CORE_ROUTER_HPP