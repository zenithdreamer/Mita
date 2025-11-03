#pragma once

#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/macro/component.hpp"
#include "api/dto.hpp"
#include "services/packet_monitor_service.hpp"
#include <chrono>
#include <iomanip>
#include <sstream>

#include OATPP_CODEGEN_BEGIN(ApiController)

class RouterApiController : public oatpp::web::server::api::ApiController {
private:
  std::chrono::steady_clock::time_point m_startTime;
  std::shared_ptr<mita::services::PacketMonitorService> m_packetMonitor;

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
  RouterApiController(const std::shared_ptr<ObjectMapper>& objectMapper,
                     std::shared_ptr<mita::services::PacketMonitorService> packetMonitor = nullptr)
    : oatpp::web::server::api::ApiController(objectMapper)
    , m_startTime(std::chrono::steady_clock::now())
    , m_packetMonitor(packetMonitor)
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

  // GET /api/packets
  ENDPOINT_INFO(getPackets) {
    info->summary = "Get captured packets";
    info->description = "Returns list of captured packets for monitoring";
    info->addResponse<Object<PacketListDto>>(Status::CODE_200, "application/json");
    info->addTag("Packets");
    info->queryParams.add<Int32>("limit").description = "Maximum number of packets to return";
    info->queryParams.add<Int32>("offset").description = "Offset for pagination";
  }
  ENDPOINT("GET", "/api/packets", getPackets, 
           REQUEST(std::shared_ptr<IncomingRequest>, request)) {
    
    // Extract query parameters manually to avoid nullable issues
    auto queryParams = request->getQueryParameters();
    Int32 limit = 100;  // default
    Int32 offset = 0;   // default
    
    if (queryParams.get("limit")) {
      try {
        limit = std::stoi(queryParams.get("limit")->c_str());
      } catch (...) {
        limit = 100;
      }
    }

    if (queryParams.get("offset")) {
      try {
        offset = std::stoi(queryParams.get("offset")->c_str());
      } catch (...) {
        offset = 0;
      }
    }
    
    printf("[API] GET /api/packets - request received (limit=%d, offset=%d)\n", limit, offset);
    fflush(stdout);
    
    auto dto = PacketListDto::createShared();
    dto->packets = oatpp::Vector<oatpp::Object<PacketInfoDto>>::createShared();

    if (!m_packetMonitor) {
      dto->total = 0;
      return createDtoResponseWithCors(Status::CODE_200, dto);
    }

    auto packets = m_packetMonitor->get_packets(static_cast<size_t>(limit), static_cast<size_t>(offset));
    dto->total = m_packetMonitor->get_packet_count();

    for (const auto& packet : packets) {
      auto packetDto = PacketInfoDto::createShared();
      packetDto->id = packet.id;
      
      auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        packet.timestamp.time_since_epoch()).count();
      packetDto->timestamp = ts;
      
      packetDto->direction = packet.direction;
      
      std::ostringstream srcAddr, dstAddr;
      srcAddr << "0x" << std::hex << std::setw(4) << std::setfill('0') << packet.source_addr;
      dstAddr << "0x" << std::hex << std::setw(4) << std::setfill('0') << packet.dest_addr;
      packetDto->sourceAddr = srcAddr.str();
      packetDto->destAddr = dstAddr.str();
      
      packetDto->messageType = packet.message_type;
      packetDto->payloadSize = static_cast<int>(packet.payload_size);
      packetDto->transport = packet.transport;
      packetDto->encrypted = packet.encrypted;
      
      // Convert raw data to hex string
      std::ostringstream hexStream;
      for (size_t i = 0; i < packet.raw_data.size(); ++i) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(packet.raw_data[i]);
        if (i < packet.raw_data.size() - 1) hexStream << " ";
      }
      packetDto->rawData = hexStream.str();
      
      packetDto->decodedHeader = packet.decoded_header;
      packetDto->decodedPayload = packet.decoded_payload;

      dto->packets->push_back(packetDto);
    }

    return createDtoResponseWithCors(Status::CODE_200, dto);
  }

  // DELETE /api/packets
  ENDPOINT_INFO(clearPackets) {
    info->summary = "Clear all captured packets";
    info->addResponse<Object<StatusDto>>(Status::CODE_200, "application/json");
    info->addTag("Packets");
  }
  ENDPOINT("DELETE", "/api/packets", clearPackets) {
    auto dto = StatusDto::createShared();
    
    if (!m_packetMonitor) {
      dto->status = "error";
      dto->message = "Packet monitor not available";
      return createDtoResponseWithCors(Status::CODE_500, dto);
    }

    m_packetMonitor->clear_packets();
    dto->status = "success";
    dto->message = "Packets cleared";
    dto->uptime = 0L;

    return createDtoResponseWithCors(Status::CODE_200, dto);
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
