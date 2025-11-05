#pragma once

#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/Types.hpp"

#include OATPP_CODEGEN_BEGIN(DTO)

class StatusDto : public oatpp::DTO {
  DTO_INIT(StatusDto, DTO)

  DTO_FIELD_INFO(status) {
    info->required = true;
  }
  DTO_FIELD(String, status);

  DTO_FIELD_INFO(message) {
    info->required = true;
  }
  DTO_FIELD(String, message);

  DTO_FIELD_INFO(uptime) {
    info->required = true;
  }
  DTO_FIELD(Int64, uptime);
};

class DeviceInfoDto : public oatpp::DTO {
  DTO_INIT(DeviceInfoDto, DTO)

  DTO_FIELD(String, id);
  DTO_FIELD(String, name);
  DTO_FIELD(String, type);  // "ble" or "wifi"
  DTO_FIELD(String, status);
  DTO_FIELD(Int64, lastSeen);
};

class RouterStatsDto : public oatpp::DTO {
  DTO_INIT(RouterStatsDto, DTO)

  DTO_FIELD(Int32, connectedDevices);
  DTO_FIELD(Int64, messagesRouted);
  DTO_FIELD(Boolean, wifiEnabled);
  DTO_FIELD(Boolean, bleEnabled);
  DTO_FIELD(Int64, uptimeSeconds);
};

class PacketInfoDto : public oatpp::DTO {
  DTO_INIT(PacketInfoDto, DTO)

  DTO_FIELD(String, id);
  DTO_FIELD(Int64, timestamp);
  DTO_FIELD(String, direction);  // "inbound", "outbound", "forwarded"
  DTO_FIELD(String, sourceAddr);
  DTO_FIELD(String, destAddr);
  DTO_FIELD(String, messageType);
  DTO_FIELD(Int32, payloadSize);
  DTO_FIELD(String, transport);  // "wifi" or "ble"
  DTO_FIELD(Boolean, encrypted);
  
  // Raw packet data (hex string)
  DTO_FIELD(String, rawData);
  
  // Decoded packet info
  DTO_FIELD(String, decodedHeader);
  DTO_FIELD(String, decodedPayload);
};

class PacketListDto : public oatpp::DTO {
  DTO_INIT(PacketListDto, DTO)

  DTO_FIELD(Vector<Object<PacketInfoDto>>, packets);
  DTO_FIELD(Int32, total);
};

// Authentication DTOs
class LoginRequestDto : public oatpp::DTO {
  DTO_INIT(LoginRequestDto, DTO)

  DTO_FIELD_INFO(username) {
    info->required = true;
    info->description = "Username for authentication";
  }
  DTO_FIELD(String, username);

  DTO_FIELD_INFO(password) {
    info->required = true;
    info->description = "Password for authentication";
  }
  DTO_FIELD(String, password);
};

class LoginResponseDto : public oatpp::DTO {
  DTO_INIT(LoginResponseDto, DTO)

  DTO_FIELD_INFO(success) {
    info->required = true;
  }
  DTO_FIELD(Boolean, success);

  DTO_FIELD_INFO(message) {
    info->required = true;
  }
  DTO_FIELD(String, message);

  DTO_FIELD(String, username);
  DTO_FIELD(Int64, userId);
};

class UserInfoDto : public oatpp::DTO {
  DTO_INIT(UserInfoDto, DTO)

  DTO_FIELD(Int64, id);
  DTO_FIELD(String, username);
  DTO_FIELD(Int64, createdAt);
};

class DashboardStatsDto : public oatpp::DTO {
  DTO_INIT(DashboardStatsDto, DTO)

  DTO_FIELD_INFO(status) {
    info->required = true;
  }
  DTO_FIELD(String, status);

  DTO_FIELD_INFO(uptime) {
    info->required = true;
  }
  DTO_FIELD(Int64, uptime);

  DTO_FIELD(Int32, connectedDevices);
  DTO_FIELD(Int64, totalPackets);
  DTO_FIELD(Int64, packetsToday);
  DTO_FIELD(Boolean, wifiEnabled);
  DTO_FIELD(Boolean, bleEnabled);
  DTO_FIELD(String, wifiStatus);
  DTO_FIELD(String, bleStatus);
  
  // System resources
  DTO_FIELD(Float32, cpuUsage);  // Percentage 0-100
  DTO_FIELD(Int64, memoryUsed);  // Bytes
  DTO_FIELD(Int64, memoryTotal); // Bytes
  DTO_FIELD(Int64, storageUsed); // Bytes
  DTO_FIELD(Int64, storageTotal); // Bytes
  
  // Network throughput
  DTO_FIELD(Int64, packetsPerSecond);
  DTO_FIELD(Float64, uploadSpeed);   // MB/s
  DTO_FIELD(Float64, downloadSpeed); // MB/s
};

class SystemResourcesDto : public oatpp::DTO {
  DTO_INIT(SystemResourcesDto, DTO)

  DTO_FIELD_INFO(cpuUsage) {
    info->description = "CPU usage percentage (0-100)";
  }
  DTO_FIELD(Float32, cpuUsage);

  DTO_FIELD_INFO(memoryUsed) {
    info->description = "Used memory in bytes";
  }
  DTO_FIELD(Int64, memoryUsed);

  DTO_FIELD_INFO(memoryTotal) {
    info->description = "Total memory in bytes";
  }
  DTO_FIELD(Int64, memoryTotal);

  DTO_FIELD_INFO(storageUsed) {
    info->description = "Used storage in bytes";
  }
  DTO_FIELD(Int64, storageUsed);

  DTO_FIELD_INFO(storageTotal) {
    info->description = "Total storage in bytes";
  }
  DTO_FIELD(Int64, storageTotal);
};

class NetworkStatsDto : public oatpp::DTO {
  DTO_INIT(NetworkStatsDto, DTO)

  DTO_FIELD(Int64, totalPackets);
  DTO_FIELD(Int64, packetsPerSecond);
  DTO_FIELD(Float64, uploadSpeed);   // MB/s
  DTO_FIELD(Float64, downloadSpeed); // MB/s
  DTO_FIELD(Int64, bytesUploaded);
  DTO_FIELD(Int64, bytesDownloaded);
};

class ProtocolInfoDto : public oatpp::DTO {
  DTO_INIT(ProtocolInfoDto, DTO)

  DTO_FIELD(String, name);
  DTO_FIELD(String, status);  // "active", "inactive", "error"
  DTO_FIELD(Int32, connectedDevices);
  DTO_FIELD(String, description);
  DTO_FIELD(Boolean, enabled);
};

class ProtocolListDto : public oatpp::DTO {
  DTO_INIT(ProtocolListDto, DTO)

  DTO_FIELD(Vector<Object<ProtocolInfoDto>>, protocols);
};

// Settings DTOs
class SettingsDto : public oatpp::DTO {
  DTO_INIT(SettingsDto, DTO)

  DTO_FIELD_INFO(wifiEnabled) {
    info->description = "WiFi transport enabled";
  }
  DTO_FIELD(Boolean, wifiEnabled);

  DTO_FIELD_INFO(bleEnabled) {
    info->description = "BLE transport enabled";
  }
  DTO_FIELD(Boolean, bleEnabled);

  DTO_FIELD_INFO(zigbeeEnabled) {
    info->description = "Zigbee transport enabled";
  }
  DTO_FIELD(Boolean, zigbeeEnabled);

  DTO_FIELD_INFO(monitorEnabled) {
    info->description = "Packet monitor enabled";
  }
  DTO_FIELD(Boolean, monitorEnabled);

  DTO_FIELD(Int64, updatedAt);
};

class UpdateSettingsRequestDto : public oatpp::DTO {
  DTO_INIT(UpdateSettingsRequestDto, DTO)

  DTO_FIELD(Boolean, wifiEnabled);
  DTO_FIELD(Boolean, bleEnabled);
  DTO_FIELD(Boolean, zigbeeEnabled);
  DTO_FIELD(Boolean, monitorEnabled);
};

// Additional DTOs for separated controllers
class ErrorDto : public oatpp::DTO {
  DTO_INIT(ErrorDto, DTO)

  DTO_FIELD(String, message);
};

class SuccessDto : public oatpp::DTO {
  DTO_INIT(SuccessDto, DTO)

  DTO_FIELD(String, message);
};

// Routing DTOs
class RouteDto : public oatpp::DTO {
  DTO_INIT(RouteDto, DTO)

  DTO_FIELD(String, destination);
  DTO_FIELD(String, next_hop);
  DTO_FIELD(Int32, metric);
  DTO_FIELD(String, interface_type);
};

class RoutingTableDto : public oatpp::DTO {
  DTO_INIT(RoutingTableDto, DTO)

  DTO_FIELD(Vector<Object<RouteDto>>, routes);
};

// Device DTOs
class DeviceDto : public oatpp::DTO {
  DTO_INIT(DeviceDto, DTO)

  DTO_FIELD(String, device_id);
  DTO_FIELD(String, device_type);
  DTO_FIELD(String, status);
  DTO_FIELD(Int64, last_seen);
  DTO_FIELD(Int32, rssi);
  DTO_FIELD(Int32, battery_level);
};

class DevicesDto : public oatpp::DTO {
  DTO_INIT(DevicesDto, DTO)

  DTO_FIELD(Vector<Object<DeviceDto>>, devices);
};

// Protocol Stats DTOs
class ProtocolStatDto : public oatpp::DTO {
  DTO_INIT(ProtocolStatDto, DTO)

  DTO_FIELD(String, protocol);
  DTO_FIELD(Int64, packets_sent);
  DTO_FIELD(Int64, packets_received);
  DTO_FIELD(Int64, bytes_sent);
  DTO_FIELD(Int64, bytes_received);
  DTO_FIELD(Int32, errors);
  DTO_FIELD(Int32, active_connections);
};

class ProtocolStatsDto : public oatpp::DTO {
  DTO_INIT(ProtocolStatsDto, DTO)

  DTO_FIELD(Vector<Object<ProtocolStatDto>>, protocols);
};

#include OATPP_CODEGEN_END(DTO)
