#pragma once

#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/macro/component.hpp"
#include "api/dto.hpp"
#include "services/packet_monitor_service.hpp"
#include "services/device_management_service.hpp"
#include "services/statistics_service.hpp"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <sys/statvfs.h>

#include OATPP_CODEGEN_BEGIN(ApiController)

/**
 * Status Controller
 * Handles all status-related endpoints (router status, device status, system resources, network stats)
 */
class StatusController : public oatpp::web::server::api::ApiController {
private:
  std::chrono::steady_clock::time_point m_startTime;
  std::shared_ptr<mita::services::PacketMonitorService> m_packetMonitor;
  std::shared_ptr<mita::services::DeviceManagementService> m_deviceManager;

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
  StatusController(const std::shared_ptr<ObjectMapper>& objectMapper,
          std::shared_ptr<mita::services::PacketMonitorService> packetMonitor = nullptr,
          std::shared_ptr<mita::services::DeviceManagementService> deviceManager = nullptr)
    : oatpp::web::server::api::ApiController(objectMapper)
    , m_startTime(std::chrono::steady_clock::now())
    , m_packetMonitor(packetMonitor)
    , m_deviceManager(deviceManager) {}

  static std::shared_ptr<StatusController> createShared(
    const std::shared_ptr<ObjectMapper>& objectMapper,
    std::shared_ptr<mita::services::PacketMonitorService> packetMonitor = nullptr,
    std::shared_ptr<mita::services::DeviceManagementService> deviceManager = nullptr
  ) {
    return std::make_shared<StatusController>(objectMapper, packetMonitor, deviceManager);
  }

  // GET /api/status (simple status)
  ENDPOINT_INFO(getStatus) {
    info->summary = "Get router status";
    info->description = "Returns the current status of the router";
    info->addResponse<Object<StatusDto>>(Status::CODE_200, "application/json");
    info->addTag("Status");
  }
  ENDPOINT("GET", "/api/status", getStatus, REQUEST(std::shared_ptr<IncomingRequest>, request)) {
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
      OATPP_LOGW("StatusController", "Device manager not initialized");
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

  // OPTIONS handler for CORS
  ENDPOINT("OPTIONS", "/api/status*", statusOptions) {
    auto response = createResponse(Status::CODE_204, "");
    response->putHeader("Access-Control-Allow-Origin", "http://localhost:5173");
    response->putHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    response->putHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Cookie");
    response->putHeader("Access-Control-Allow-Credentials", "true");
    response->putHeader("Access-Control-Max-Age", "86400");
    response->putHeader("Connection", "close");
    return response;
  }

  ENDPOINT_INFO(getStatistics) {
    info->summary = "Get comprehensive router statistics including security metrics";
    info->addResponse<Object<RouterStatisticsDto>>(Status::CODE_200, "application/json");
    info->addResponse<Object<ErrorDto>>(Status::CODE_500, "application/json");
    info->addTag("Status");
  }
  ENDPOINT("GET", "/api/statistics", getStatistics) {
    auto dto = RouterStatisticsDto::createShared();
    
    if (m_deviceManager) {
      auto stats = m_deviceManager->get_statistics_snapshot();
      
      // Basic operational metrics (map from actual RouterStatisticsSnapshot fields)
      dto->totalPacketsReceived = stats.packets_received;
      dto->totalPacketsSent = stats.packets_sent;
      dto->totalBytesReceived = stats.bytes_transferred;  // Using bytes_transferred for total
      dto->totalBytesSent = stats.bytes_transferred;      // Same counter for both in current impl
      dto->packetsPerSecond = 0.0;  // Calculate if needed, not in snapshot
      
      // Security metrics - NEW
      dto->sequenceGapsDetected = stats.sequence_gaps_detected;
      dto->replayAttemptsBlocked = stats.replay_attempts_blocked;
      dto->stalePacketsDropped = stats.stale_packets_dropped;
      dto->sessionRekeysCompleted = stats.session_rekeys_completed;
      
      // Device statistics (get from device manager)
      dto->activeDevices = m_deviceManager->get_device_count();
      dto->totalDevicesRegistered = m_deviceManager->get_device_count();  // Same for now
      
      // Error statistics
      dto->authenticationFailures = stats.handshakes_failed;
      dto->invalidPacketsReceived = stats.protocol_errors;
      dto->droppedPackets = stats.packets_dropped;
      
      // Transport-specific stats - would need transport stats API
      // For now, use 0 or derive from overall stats
      dto->wifiPacketsReceived = static_cast<int64_t>(0);
      dto->wifiPacketsSent = static_cast<int64_t>(0);
      dto->blePacketsReceived = static_cast<int64_t>(0);
      dto->blePacketsSent = static_cast<int64_t>(0);
      
      // Uptime
      dto->uptimeSeconds = stats.get_uptime_seconds();
    }
    
    return createDtoResponseWithCors(Status::CODE_200, dto);
  }
};

#include OATPP_CODEGEN_END(ApiController)
