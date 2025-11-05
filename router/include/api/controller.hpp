#pragma once

#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/macro/component.hpp"
#include "api/dto.hpp"
#include "services/packet_monitor_service.hpp"
#include "services/device_management_service.hpp"
#include "services/settings_service.hpp"
#include <chrono>

#include OATPP_CODEGEN_BEGIN(ApiController)

// Forward declaration
namespace mita {
namespace core {
class MitaRouter;
}
}

/**
 * Router API Controller - Main controller for CORS handling
 * Note: Specific API endpoints have been moved to specialized controllers:
 * - StatusController: /api/status/... endpoints
 * - PacketsController: /api/packets/... endpoints
 * - RoutingController: /api/routing-table/... endpoints
 * - DevicesController: /api/devices/... endpoints
 * - ProtocolsController: /api/protocols/... endpoints
 * - SettingsController: /api/settings/... endpoints
 */
class RouterApiController : public oatpp::web::server::api::ApiController {
private:
  std::chrono::steady_clock::time_point m_startTime;
  std::shared_ptr<mita::services::PacketMonitorService> m_packetMonitor;
  std::shared_ptr<mita::services::DeviceManagementService> m_deviceManager;
  std::shared_ptr<mita::SettingsService> m_settingsService;
  mita::core::MitaRouter* m_router;

  // Helper to add CORS headers
  template<class T>
  std::shared_ptr<OutgoingResponse> createDtoResponseWithCors(const Status& status, const T& dto) {
    auto response = createDtoResponse(status, dto);
    response->putHeader("Access-Control-Allow-Origin", "http://localhost:5173");
    response->putHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    response->putHeader("Access-Control-Allow-Headers", "Content-Type, Cookie");
    response->putHeader("Access-Control-Allow-Credentials", "true");
    response->putHeader("Connection", "close");
    return response;
  }

public:
  RouterApiController(const std::shared_ptr<ObjectMapper>& objectMapper,
                     std::shared_ptr<mita::services::PacketMonitorService> packetMonitor = nullptr,
                     std::shared_ptr<mita::services::DeviceManagementService> deviceManager = nullptr,
                     std::shared_ptr<mita::SettingsService> settingsService = nullptr,
                     mita::core::MitaRouter* router = nullptr)
    : oatpp::web::server::api::ApiController(objectMapper)
    , m_startTime(std::chrono::steady_clock::now())
    , m_packetMonitor(packetMonitor)
    , m_deviceManager(deviceManager)
    , m_settingsService(settingsService)
    , m_router(router)
  {}

  // OPTIONS handler for CORS preflight requests
  ENDPOINT_INFO(options) {
    info->summary = "CORS preflight handler";
    info->description = "Handles CORS preflight OPTIONS requests";
    info->addResponse<String>(Status::CODE_204, "text/plain");
    info->addTag("CORS");
  }
  ENDPOINT("OPTIONS", "*", options) {
    auto response = createResponse(Status::CODE_204, "");
    response->putHeader("Access-Control-Allow-Origin", "http://localhost:5173");
    response->putHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    response->putHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Cookie");
    response->putHeader("Access-Control-Allow-Credentials", "true");
    response->putHeader("Access-Control-Max-Age", "86400");
    response->putHeader("Connection", "close");
    return response;
  }
};

#include OATPP_CODEGEN_END(ApiController)
