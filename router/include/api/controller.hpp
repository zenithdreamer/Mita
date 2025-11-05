#pragma once

#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/macro/component.hpp"
#include "api/dto.hpp"
#include "services/packet_monitor_service.hpp"
#include "services/device_management_service.hpp"
#include "services/settings_service.hpp"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <sys/statvfs.h>

#include OATPP_CODEGEN_BEGIN(ApiController)

// Forward declaration
namespace mita {
namespace core {
class MitaRouter;
}
}

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
    response->putHeader("Connection", "close");  // Force close to avoid keep-alive blocking
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

  // GET /api/status (simple status)
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

  // GET /api/status/devices (device connection status)
  ENDPOINT_INFO(getDeviceStatus) {
    info->summary = "Get connected devices status";
    info->description = "Returns information about connected devices across all transports";
    info->addResponse<Object<DashboardStatsDto>>(Status::CODE_200, "application/json");
    info->addTag("Status");
  }
  ENDPOINT("GET", "/api/status/devices", getDeviceStatus) {
    printf("[API] GET /api/status/devices - request received\n");
    fflush(stdout);

    auto dto = DashboardStatsDto::createShared();
    dto->status = "running";

    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - m_startTime);
    dto->uptime = uptime.count();

    // Get real device counts
    if (m_deviceManager) {
      dto->connectedDevices = static_cast<Int32>(m_deviceManager->get_device_count());
    } else {
      dto->connectedDevices = 0;
    }

    // Protocol status (WiFi and BLE are enabled if we have the transports)
    dto->wifiEnabled = true;
    dto->bleEnabled = true;
    dto->wifiStatus = "Active";
    dto->bleStatus = "Active";

    // Get packet statistics with real metrics
    if (m_packetMonitor) {
      auto metrics = m_packetMonitor->get_network_metrics();
      dto->totalPackets = static_cast<Int64>(m_packetMonitor->get_packet_count());
      dto->packetsToday = dto->totalPackets;
      dto->packetsPerSecond = static_cast<Int64>(metrics.packets_per_second);
    } else {
      dto->totalPackets = static_cast<Int64>(0L);
      dto->packetsToday = static_cast<Int64>(0L);
      dto->packetsPerSecond = static_cast<Int64>(0L);
    }

    return createDtoResponseWithCors(Status::CODE_200, dto);
  }

  // GET /api/status/system (system resources)
  ENDPOINT_INFO(getSystemStatus) {
    info->summary = "Get system resource status";
    info->description = "Returns CPU, memory, and storage usage";
    info->addResponse<Object<SystemResourcesDto>>(Status::CODE_200, "application/json");
    info->addTag("Status");
  }
  ENDPOINT("GET", "/api/status/system", getSystemStatus) {
    printf("[API] GET /api/status/system - request received\n");
    fflush(stdout);

    auto dto = SystemResourcesDto::createShared();

    // Read memory info from /proc/meminfo (Linux)
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo.is_open()) {
      std::string line;
      long memTotal = 0, memFree = 0, memAvailable = 0;
      
      while (std::getline(meminfo, line)) {
        if (line.find("MemTotal:") == 0) {
          sscanf(line.c_str(), "MemTotal: %ld kB", &memTotal);
        } else if (line.find("MemAvailable:") == 0) {
          sscanf(line.c_str(), "MemAvailable: %ld kB", &memAvailable);
        } else if (line.find("MemFree:") == 0) {
          sscanf(line.c_str(), "MemFree: %ld kB", &memFree);
        }
      }
      meminfo.close();
      
      dto->memoryTotal = static_cast<Int64>(memTotal * 1024);
      long memUsed = (memTotal - memAvailable) * 1024;
      dto->memoryUsed = static_cast<Int64>(memUsed > 0 ? memUsed : 0);
    } else {
      dto->memoryTotal = static_cast<Int64>(4294967296L);
      dto->memoryUsed = static_cast<Int64>(2576980377L);
    }

    // Read CPU usage from /proc/stat
    std::ifstream stat("/proc/stat");
    if (stat.is_open()) {
      std::string line;
      std::getline(stat, line);
      stat.close();
      
      unsigned long long user, nice, system, idle;
      sscanf(line.c_str(), "cpu %llu %llu %llu %llu", &user, &nice, &system, &idle);
      
      unsigned long long total = user + nice + system + idle;
      unsigned long long active = user + nice + system;
      
      if (total > 0) {
        dto->cpuUsage = static_cast<Float32>((active * 100.0) / total);
      } else {
        dto->cpuUsage = static_cast<Float32>(34.0f);
      }
    } else {
      dto->cpuUsage = static_cast<Float32>(34.0f);
    }

    // Read storage info from statvfs
    struct statvfs stat_buf;
    if (statvfs("/", &stat_buf) == 0) {
      dto->storageTotal = static_cast<Int64>(stat_buf.f_blocks) * static_cast<Int64>(stat_buf.f_frsize);
      dto->storageUsed = static_cast<Int64>(stat_buf.f_blocks - stat_buf.f_bfree) * static_cast<Int64>(stat_buf.f_frsize);
    } else {
      dto->storageTotal = static_cast<Int64>(34359738368L);
      dto->storageUsed = static_cast<Int64>(13743895347L);
    }

    return createDtoResponseWithCors(Status::CODE_200, dto);
  }

  // GET /api/status/network (network statistics)
  ENDPOINT_INFO(getNetworkStatus) {
    info->summary = "Get network statistics";
    info->description = "Returns packet counts and throughput information";
    info->addResponse<Object<NetworkStatsDto>>(Status::CODE_200, "application/json");
    info->addTag("Status");
  }
  ENDPOINT("GET", "/api/status/network", getNetworkStatus) {
    printf("[API] GET /api/status/network - request received\n");
    fflush(stdout);

    auto dto = NetworkStatsDto::createShared();

    if (m_packetMonitor) {
      // Get real network metrics from packet monitor
      auto metrics = m_packetMonitor->get_network_metrics();
      
      dto->totalPackets = static_cast<Int64>(m_packetMonitor->get_packet_count());
      dto->packetsPerSecond = static_cast<Int64>(metrics.packets_per_second);
      dto->uploadSpeed = static_cast<Float64>(metrics.upload_speed_mbps);
      dto->downloadSpeed = static_cast<Float64>(metrics.download_speed_mbps);
      dto->bytesUploaded = static_cast<Int64>(metrics.total_bytes_uploaded);
      dto->bytesDownloaded = static_cast<Int64>(metrics.total_bytes_downloaded);
    } else {
      dto->totalPackets = static_cast<Int64>(0L);
      dto->packetsPerSecond = static_cast<Int64>(0L);
      dto->uploadSpeed = static_cast<Float64>(0.0);
      dto->downloadSpeed = static_cast<Float64>(0.0);
      dto->bytesUploaded = static_cast<Int64>(0L);
      dto->bytesDownloaded = static_cast<Int64>(0L);
    }

    return createDtoResponseWithCors(Status::CODE_200, dto);
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
    
    // Convert oatpp primitive types to native ints before printing to avoid format warnings
    int limitVal = 0;
    int offsetVal = 0;
    try {
      limitVal = static_cast<int>(limit);
    } catch (...) {
      limitVal = 0;
    }
    try {
      offsetVal = static_cast<int>(offset);
    } catch (...) {
      offsetVal = 0;
    }

    printf("[API] GET /api/packets - request received (limit=%d, offset=%d)\n", limitVal, offsetVal);
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

  // GET /api/protocols
  ENDPOINT_INFO(getProtocols) {
    info->summary = "Get protocol status";
    info->description = "Returns status of supported protocols (WiFi, BLE, Zigbee, etc.)";
    info->addResponse<Object<ProtocolListDto>>(Status::CODE_200, "application/json");
    info->addTag("Protocols");
  }
  ENDPOINT("GET", "/api/protocols", getProtocols) {
    printf("[API] GET /api/protocols - request received\n");
    fflush(stdout);

    auto dto = ProtocolListDto::createShared();
    dto->protocols = oatpp::Vector<oatpp::Object<ProtocolInfoDto>>::createShared();

    // Get real device counts from device manager
    int wifiCount = 0;
    int bleCount = 0;
    
    if (m_deviceManager) {
      wifiCount = m_deviceManager->get_device_count_by_transport(mita::core::TransportType::WIFI);
      bleCount = m_deviceManager->get_device_count_by_transport(mita::core::TransportType::BLE);
    }

    // WiFi Protocol
    auto wifi = ProtocolInfoDto::createShared();
    wifi->name = "WiFi (802.11ax)";
    wifi->status = (wifiCount > 0) ? "active" : "idle";
    wifi->connectedDevices = wifiCount;
    wifi->description = "2.4GHz & 5GHz dual-band wireless";
    wifi->enabled = true;
    dto->protocols->push_back(wifi);

    // Bluetooth LE Protocol
    auto ble = ProtocolInfoDto::createShared();
    ble->name = "Bluetooth LE";
    ble->status = (bleCount > 0) ? "active" : "idle";
    ble->connectedDevices = bleCount;
    ble->description = "Low energy Bluetooth 5.3";
    ble->enabled = true;
    dto->protocols->push_back(ble);

    // Zigbee Protocol (not yet implemented in device manager)
    auto zigbee = ProtocolInfoDto::createShared();
    zigbee->name = "Zigbee 3.0";
    zigbee->status = "idle";
    zigbee->connectedDevices = 0;
    zigbee->description = "Low-power mesh networking";
    zigbee->enabled = true;
    dto->protocols->push_back(zigbee);

    return createDtoResponseWithCors(Status::CODE_200, dto);
  }

  // GET /api/settings
  ENDPOINT_INFO(getSettings) {
    info->summary = "Get transport settings";
    info->description = "Returns current enabled/disabled state of all transports";
    info->addResponse<Object<SettingsDto>>(Status::CODE_200, "application/json");
    info->addTag("Settings");
  }
  ENDPOINT("GET", "/api/settings", getSettings) {
    printf("[API] GET /api/settings - request received\n");
    fflush(stdout);

    auto dto = SettingsDto::createShared();

    if (!m_settingsService) {
      dto->wifiEnabled = false;
      dto->bleEnabled = false;
      dto->zigbeeEnabled = false;
      dto->updatedAt = 0L;
      return createDtoResponseWithCors(Status::CODE_200, dto);
    }

    try {
      auto settings = m_settingsService->getSettings();
      dto->wifiEnabled = settings.wifi_enabled != 0;
      dto->bleEnabled = settings.ble_enabled != 0;
      dto->zigbeeEnabled = settings.zigbee_enabled != 0;
      dto->monitorEnabled = settings.monitor_enabled != 0;
      dto->updatedAt = static_cast<int64_t>(settings.updated_at);
    } catch (const std::exception& e) {
      printf("[API] ERROR: Failed to get settings: %s\n", e.what());
      fflush(stdout);
      dto->wifiEnabled = false;
      dto->bleEnabled = false;
      dto->zigbeeEnabled = false;
      dto->monitorEnabled = false;
      dto->updatedAt = 0L;
    }

    return createDtoResponseWithCors(Status::CODE_200, dto);
  }

  // PUT /api/settings
  ENDPOINT_INFO(updateSettings) {
    info->summary = "Update transport settings";
    info->description = "Enable or disable transports (WiFi, BLE, Zigbee) and apply changes immediately";
    info->addResponse<Object<SettingsDto>>(Status::CODE_200, "application/json");
    info->addResponse<Object<StatusDto>>(Status::CODE_500, "application/json");
    info->addTag("Settings");
  }
  ENDPOINT("PUT", "/api/settings", updateSettings,
           BODY_DTO(Object<UpdateSettingsRequestDto>, body)) {
    printf("[API] PUT /api/settings - request received\n");
    fflush(stdout);

    if (!m_settingsService) {
      auto errorDto = StatusDto::createShared();
      errorDto->status = "error";
      errorDto->message = "Settings service not available";
      errorDto->uptime = 0L;
      return createDtoResponseWithCors(Status::CODE_500, errorDto);
    }

    if (!m_router) {
      auto errorDto = StatusDto::createShared();
      errorDto->status = "error";
      errorDto->message = "Router not available";
      errorDto->uptime = 0L;
      return createDtoResponseWithCors(Status::CODE_500, errorDto);
    }

    try {
      // Extract boolean values from request
      bool wifiEnabled = body->wifiEnabled ? static_cast<bool>(body->wifiEnabled) : false;
      bool bleEnabled = body->bleEnabled ? static_cast<bool>(body->bleEnabled) : false;
      bool zigbeeEnabled = body->zigbeeEnabled ? static_cast<bool>(body->zigbeeEnabled) : false;
      bool monitorEnabled = body->monitorEnabled ? static_cast<bool>(body->monitorEnabled) : false;

      // Get current settings to detect changes
      auto currentSettings = m_settingsService->getSettings();
      bool wifiWasEnabled = currentSettings.wifi_enabled != 0;
      bool bleWasEnabled = currentSettings.ble_enabled != 0;
      bool monitorWasEnabled = currentSettings.monitor_enabled != 0;

      // Update settings in database
      m_settingsService->updateSettings(wifiEnabled, bleEnabled, zigbeeEnabled, monitorEnabled);

      // Apply transport changes immediately
      bool success = true;
      std::string message = "Settings updated successfully. Transport changes: ";

      // Handle WiFi transport changes
      if (wifiEnabled && !wifiWasEnabled) {
        printf("[API] Starting WiFi transport...\n");
        fflush(stdout);
        if (m_router->start_wifi_transport()) {
          message += "WiFi started, ";
        } else {
          message += "WiFi start failed, ";
          success = false;
        }
      } else if (!wifiEnabled && wifiWasEnabled) {
        printf("[API] Stopping WiFi transport...\n");
        fflush(stdout);
        if (m_router->stop_wifi_transport()) {
          message += "WiFi stopped, ";
        } else {
          message += "WiFi stop failed, ";
          success = false;
        }
      }

      // Handle BLE transport changes
      if (bleEnabled && !bleWasEnabled) {
        printf("[API] Starting BLE transport...\n");
        fflush(stdout);
        if (m_router->start_ble_transport()) {
          message += "BLE started, ";
        } else {
          message += "BLE start failed, ";
          success = false;
        }
      } else if (!bleEnabled && bleWasEnabled) {
        printf("[API] Stopping BLE transport...\n");
        fflush(stdout);
        if (m_router->stop_ble_transport()) {
          message += "BLE stopped, ";
        } else {
          message += "BLE stop failed, ";
          success = false;
        }
      }

      // Remove trailing comma and space
      if (message.back() == ' ') {
        message.pop_back();
        message.pop_back();
      }

      // Handle packet monitor changes
      if (monitorEnabled && !monitorWasEnabled) {
        printf("[API] Enabling packet monitor...\n");
        fflush(stdout);
        if (m_router && m_router->get_packet_monitor()) {
          m_router->get_packet_monitor()->enable();
          message += "Monitor enabled, ";
        }
      } else if (!monitorEnabled && monitorWasEnabled) {
        printf("[API] Disabling packet monitor...\n");
        fflush(stdout);
        if (m_router && m_router->get_packet_monitor()) {
          m_router->get_packet_monitor()->disable();
          message += "Monitor disabled, ";
        }
      }

      // Remove trailing comma and space
      if (message.back() == ' ') {
        message.pop_back();
        message.pop_back();
      }

      // Return updated settings
      auto dto = SettingsDto::createShared();
      auto settings = m_settingsService->getSettings();
      dto->wifiEnabled = settings.wifi_enabled != 0;
      dto->bleEnabled = settings.ble_enabled != 0;
      dto->zigbeeEnabled = settings.zigbee_enabled != 0;
      dto->monitorEnabled = settings.monitor_enabled != 0;
      dto->updatedAt = static_cast<int64_t>(settings.updated_at);

      printf("[API] %s\n", message.c_str());
      fflush(stdout);

      return createDtoResponseWithCors(success ? Status::CODE_200 : Status::CODE_500, dto);
    } catch (const std::exception& e) {
      printf("[API] ERROR: Failed to update settings: %s\n", e.what());
      fflush(stdout);

      auto errorDto = StatusDto::createShared();
      errorDto->status = "error";
      errorDto->message = std::string("Failed to update settings: ") + e.what();
      errorDto->uptime = 0L;
      return createDtoResponseWithCors(Status::CODE_500, errorDto);
    }
  }

  // OPTIONS handler for CORS
  ENDPOINT("OPTIONS", "*", options) {
    auto response = createResponse(Status::CODE_204, "");
    response->putHeader("Access-Control-Allow-Origin", "http://localhost:5173");
    response->putHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    response->putHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Cookie");
    response->putHeader("Access-Control-Allow-Credentials", "true");
    response->putHeader("Access-Control-Max-Age", "86400");
    response->putHeader("Connection", "close");  // Force close to avoid keep-alive blocking
    return response;
  }
};

#include OATPP_CODEGEN_END(ApiController)
