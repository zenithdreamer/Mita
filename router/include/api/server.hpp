#pragma once

#include "oatpp/web/server/HttpConnectionHandler.hpp"
#include "oatpp/web/server/HttpRouter.hpp"
#include "oatpp/network/tcp/server/ConnectionProvider.hpp"
#include "oatpp/network/Server.hpp"
#include "oatpp/parser/json/mapping/ObjectMapper.hpp"
#include "oatpp-swagger/Controller.hpp"
#include "oatpp-swagger/Resources.hpp"
#include "api/controller.hpp"
#include "services/packet_monitor_service.hpp"
#include <memory>
#include <thread>
#include <chrono>
#include <vector>
#include <atomic>

class ApiServer {
private:
  std::shared_ptr<oatpp::network::tcp::server::ConnectionProvider> m_connectionProvider;
  std::shared_ptr<oatpp::web::server::HttpConnectionHandler> m_connectionHandler;
  std::vector<std::thread> m_workerThreads;
  std::atomic<bool> m_running;
  std::shared_ptr<mita::services::PacketMonitorService> m_packetMonitor;
  static constexpr size_t NUM_WORKER_THREADS = 4;

public:
  ApiServer(std::shared_ptr<mita::services::PacketMonitorService> packetMonitor = nullptr) 
    : m_running(false), m_packetMonitor(packetMonitor) {}

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

    // Create API Controller with packet monitor
    auto apiController = std::make_shared<RouterApiController>(objectMapper, m_packetMonitor);
    router->addController(apiController);

    // Create Swagger documentation info
    auto docInfo = oatpp::swagger::DocumentInfo::createShared();
    docInfo->header = oatpp::swagger::DocumentHeader::createShared();
    docInfo->header->title = "Mita Router API";
    docInfo->header->description = "BLE/WiFi Router REST API";
    docInfo->header->version = "1.0.0";

    // Create Swagger UI controller with embedded resources
    #ifdef OATPP_SWAGGER_RES_PATH
    auto swaggerResources = oatpp::swagger::Resources::streamResources(OATPP_SWAGGER_RES_PATH);
    #else
    auto swaggerResources = oatpp::swagger::Resources::streamResources(nullptr);
    #endif

    auto swaggerController = oatpp::swagger::Controller::createShared(
      apiController->getEndpoints(),
      docInfo,
      swaggerResources
    );
    router->addController(swaggerController);

    // Create connection provider
    m_connectionProvider = oatpp::network::tcp::server::ConnectionProvider::createShared(
      {host, port, oatpp::network::Address::IP_4}
    );

    // Create connection handler
    m_connectionHandler = oatpp::web::server::HttpConnectionHandler::createShared(router);

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

      printf("[API] HTTP Server stopped\n");
    }
  }

  bool isRunning() const {
    return m_running;
  }
};
