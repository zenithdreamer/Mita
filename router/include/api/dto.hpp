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

#include OATPP_CODEGEN_END(DTO)
