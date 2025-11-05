#pragma once

#include "oatpp/web/server/HttpConnectionHandler.hpp"
#include "oatpp/web/server/HttpRouter.hpp"
#include "oatpp/network/tcp/server/ConnectionProvider.hpp"
#include "oatpp/network/Server.hpp"
#include "oatpp/parser/json/mapping/ObjectMapper.hpp"
#include "oatpp-swagger/Controller.hpp"
#include "oatpp-swagger/Resources.hpp"
#include "api/controller.hpp"
#include "api/controllers/status_controller.hpp"
#include "api/controllers/packets_controller.hpp"
#include "api/controllers/routing_controller.hpp"
#include "api/controllers/devices_controller.hpp"
#include "api/controllers/protocols_controller.hpp"
#include "api/controllers/settings_controller.hpp"
#include "api/auth_controller.hpp"
#include "api/auth_interceptor.hpp"
#include "services/packet_monitor_service.hpp"
#include "services/device_management_service.hpp"
#include "services/auth_service.hpp"
#include "services/settings_service.hpp"
#include <memory>
#include <thread>
#include <chrono>
#include <vector>
#include <atomic>

// Forward declaration
namespace mita {
namespace core {
class MitaRouter;
}
}

class ApiServer {
private:
  std::shared_ptr<oatpp::network::tcp::server::ConnectionProvider> m_connectionProvider;
  std::shared_ptr<oatpp::web::server::HttpConnectionHandler> m_connectionHandler;
  std::vector<std::thread> m_workerThreads;
  std::thread m_cleanupThread;
  std::atomic<bool> m_running;
  std::shared_ptr<mita::services::PacketMonitorService> m_packetMonitor;
  std::shared_ptr<mita::services::DeviceManagementService> m_deviceManager;
  std::shared_ptr<mita::AuthService> m_authService;
  std::shared_ptr<mita::SettingsService> m_settingsService;
  mita::core::MitaRouter* m_router;
  static constexpr size_t NUM_WORKER_THREADS = 4;

public:
  ApiServer(std::shared_ptr<mita::services::PacketMonitorService> packetMonitor = nullptr,
            std::shared_ptr<mita::services::DeviceManagementService> deviceManager = nullptr,
            mita::core::MitaRouter* router = nullptr)
    : m_running(false), m_packetMonitor(packetMonitor), m_deviceManager(deviceManager), m_router(router) {
    // Initialize authentication service
    try {
      m_authService = std::make_shared<mita::AuthService>("data/router.db");

      // Initialize settings service with the same storage
      auto storage = std::make_shared<mita::db::Storage>(mita::db::initStorage("data/router.db"));
      storage->sync_schema();
      m_settingsService = std::make_shared<mita::SettingsService>(storage);
    } catch (const std::exception& e) {
      printf("[ERROR] Failed to initialize authentication service: %s\n", e.what());
      throw;
    }
  }

  ~ApiServer() {
    stop();
  }

  void start(const std::string& host = "0.0.0.0", uint16_t port = 8080) {
    if (m_running.exchange(true)) {
      return;
    }

    // Create ObjectMapper
    auto objectMapper = oatpp::parser::json::mapping::ObjectMapper::createShared();

    // Create Router
    auto router = oatpp::web::server::HttpRouter::createShared();

    // Create authentication interceptor
    auto authInterceptor = std::make_shared<AuthInterceptor>(m_authService);

    // Create API Controllers
    auto apiController = std::make_shared<RouterApiController>(objectMapper, m_packetMonitor, m_deviceManager, m_settingsService, m_router);
    router->addController(apiController);

    // Create specialized controllers
    auto statusController = StatusController::createShared(objectMapper);
    router->addController(statusController);

    auto packetsController = PacketsController::createShared(objectMapper, m_packetMonitor);
    router->addController(packetsController);

    auto routingController = RoutingController::createShared(objectMapper);
    router->addController(routingController);

    auto devicesController = DevicesController::createShared(objectMapper);
    router->addController(devicesController);

    auto protocolsController = ProtocolsController::createShared(objectMapper, m_deviceManager);
    router->addController(protocolsController);

    auto settingsController = SettingsController::createShared(objectMapper, m_settingsService, m_router);
    router->addController(settingsController);

    // Create Auth Controller
    auto authController = std::make_shared<AuthController>(objectMapper, m_authService);
    router->addController(authController);

    // Create Swagger documentation info
    auto docInfo = oatpp::swagger::DocumentInfo::createShared();
    docInfo->header = oatpp::swagger::DocumentHeader::createShared();
    docInfo->header->title = "Mita Router API";
    docInfo->header->description = "BLE/WiFi Router REST API with Authentication";
    docInfo->header->version = "1.0.0";

    // Create Swagger UI controller with embedded resources
    #ifdef OATPP_SWAGGER_RES_PATH
    auto swaggerResources = oatpp::swagger::Resources::streamResources(OATPP_SWAGGER_RES_PATH);
    #else
    auto swaggerResources = oatpp::swagger::Resources::streamResources(nullptr);
    #endif

    // Combine endpoints from all controllers for Swagger
    auto apiEndpoints = apiController->getEndpoints();
    apiEndpoints.append(statusController->getEndpoints());
    apiEndpoints.append(packetsController->getEndpoints());
    apiEndpoints.append(routingController->getEndpoints());
    apiEndpoints.append(devicesController->getEndpoints());
    apiEndpoints.append(protocolsController->getEndpoints());
    apiEndpoints.append(settingsController->getEndpoints());
    apiEndpoints.append(authController->getEndpoints());

    auto swaggerController = oatpp::swagger::Controller::createShared(
      apiEndpoints,
      docInfo,
      swaggerResources
    );
    router->addController(swaggerController);

    // Create connection provider
    m_connectionProvider = oatpp::network::tcp::server::ConnectionProvider::createShared(
      {host, port, oatpp::network::Address::IP_4}
    );

    // Create connection handler with authentication interceptor
    m_connectionHandler = oatpp::web::server::HttpConnectionHandler::createShared(router);
    m_connectionHandler->addRequestInterceptor(authInterceptor);

    printf("[API] HTTP Server starting on http://%s:%d\n", host.c_str(), port);
    printf("[API] API endpoints: http://%s:%d/api/*\n", host.c_str(), port);
    printf("[API] Swagger UI: http://%s:%d/swagger/ui\n", host.c_str(), port);
    printf("[API] OpenAPI JSON: http://%s:%d/api-docs/oas-3.0.0.json\n", host.c_str(), port);

    // Spawn multiple worker threads to handle connections concurrently
    for (size_t i = 0; i < NUM_WORKER_THREADS; ++i) {
      m_workerThreads.emplace_back([this]() {
        while (m_running) {
          // Each worker thread accepts and handles one connection at a time
          auto connection = m_connectionProvider->get();
          if (connection) {
            m_connectionHandler->handleConnection(connection, nullptr);
          } else {
            // No connection available, sleep briefly
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
          }
        }
      });
    }

    printf("[API] HTTP Server started with %zu worker threads\n", NUM_WORKER_THREADS);

    // Start background session cleanup thread
    m_cleanupThread = std::thread([this]() {
      while (m_running) {
        // Cleanup expired sessions every 5 minutes
        std::this_thread::sleep_for(std::chrono::minutes(5));
        if (m_running && m_authService) {
          m_authService->cleanupExpiredSessions();
        }
      }
    });
  }

  void stop() {
    if (m_running.exchange(false)) {
      // Stop accepting new connections
      if (m_connectionProvider) {
        m_connectionProvider->stop();
      }

      // Join all worker threads
      for (auto& thread : m_workerThreads) {
        if (thread.joinable()) {
          thread.join();
        }
      }
      m_workerThreads.clear();

      // Join cleanup thread
      if (m_cleanupThread.joinable()) {
        m_cleanupThread.join();
      }

      printf("[API] HTTP Server stopped\n");
    }
  }

  bool isRunning() const {
    return m_running;
  }
};
