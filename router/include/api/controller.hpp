#pragma once

#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/macro/component.hpp"
#include "api/dto.hpp"
#include <chrono>

#include OATPP_CODEGEN_BEGIN(ApiController)

class RouterApiController : public oatpp::web::server::api::ApiController {
private:
  std::chrono::steady_clock::time_point m_startTime;

  // Helper to add CORS headers
  template<class T>
  std::shared_ptr<OutgoingResponse> createDtoResponseWithCors(const Status& status, const T& dto) {
    auto response = createDtoResponse(status, dto);
    response->putHeader("Access-Control-Allow-Origin", "*");
    response->putHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    response->putHeader("Access-Control-Allow-Headers", "Content-Type");
    response->putHeader("Connection", "close");  // Force close to avoid keep-alive blocking
    return response;
  }

public:
  RouterApiController(const std::shared_ptr<ObjectMapper>& objectMapper)
    : oatpp::web::server::api::ApiController(objectMapper)
    , m_startTime(std::chrono::steady_clock::now())
  {}

  // GET /api/status
  ENDPOINT_INFO(getStatus) {
    info->summary = "Get router status";
    info->description = "Returns the current status of the router";
    info->addResponse<Object<StatusDto>>(Status::CODE_200, "application/json");
    info->addTag("Router");
  }
  ENDPOINT("GET", "/api/status", getStatus, REQUEST(std::shared_ptr<IncomingRequest>, request)) {
    printf("[API] GET /api/status - request received from %s\n",
           request->getHeader("User-Agent")->c_str());
    printf("[API] Connection header from client: %s\n",
           request->getHeader("Connection") ? request->getHeader("Connection")->c_str() : "none");
    fflush(stdout);

    auto dto = StatusDto::createShared();
    dto->status = "running";
    dto->message = "Router is operational";

    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - m_startTime);
    dto->uptime = uptime.count();

    printf("[API] GET /api/status - sending response (uptime=%ld) with Connection: close\n", uptime.count());
    fflush(stdout);

    auto response = createDtoResponseWithCors(Status::CODE_200, dto);
    printf("[API] Response created, returning to handler\n");
    fflush(stdout);
    return response;
  }

  // OPTIONS handler for CORS
  ENDPOINT("OPTIONS", "*", options) {
    auto response = createResponse(Status::CODE_204, "");
    response->putHeader("Access-Control-Allow-Origin", "*");
    response->putHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    response->putHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    response->putHeader("Access-Control-Max-Age", "86400");
    response->putHeader("Connection", "close");  // Force close to avoid keep-alive blocking
    return response;
  }
};

#include OATPP_CODEGEN_END(ApiController)
