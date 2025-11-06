#pragma once

#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/macro/component.hpp"
#include "api/dto.hpp"
#include "services/device_management_service.hpp"

#include OATPP_CODEGEN_BEGIN(ApiController)

/**
 * Protocols Controller - Handles protocol statistics and management endpoints
 */
class ProtocolsController : public oatpp::web::server::api::ApiController {
private:
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
    ProtocolsController(const std::shared_ptr<ObjectMapper>& objectMapper,
                       std::shared_ptr<mita::services::DeviceManagementService> deviceManager = nullptr)
        : oatpp::web::server::api::ApiController(objectMapper)
        , m_deviceManager(deviceManager) {}

    static std::shared_ptr<ProtocolsController> createShared(
        const std::shared_ptr<ObjectMapper>& objectMapper,
        std::shared_ptr<mita::services::DeviceManagementService> deviceManager = nullptr
    ) {
        return std::make_shared<ProtocolsController>(objectMapper, deviceManager);
    }

    ENDPOINT_INFO(getProtocols) {
        info->summary = "Get protocols";
        info->description = "Returns status of supported protocols (WiFi, BLE, Zigbee, etc.)";
        info->addResponse<Object<ProtocolListDto>>(Status::CODE_200, "application/json");
        info->addTag("Protocols");
    }
    ENDPOINT("GET", "/api/protocols", getProtocols) {
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

    ENDPOINT_INFO(getProtocolStats) {
        info->summary = "Get protocol statistics";
        info->description = "Retrieve statistics for all supported protocols (BLE, WiFi, LoRa)";
        info->addResponse<Object<ProtocolStatsDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<ErrorDto>>(Status::CODE_500, "application/json");
        info->addTag("Protocols");
    }
    ENDPOINT("GET", "/api/protocols/stats", getProtocolStats) {
        try {
            // TODO: Implement actual protocol stats retrieval
            
            auto response = ProtocolStatsDto::createShared();
            
            // BLE stats
            auto bleStats = ProtocolStatDto::createShared();
            bleStats->protocol = "BLE";
            bleStats->packets_sent = 0L;
            bleStats->packets_received = 0L;
            bleStats->bytes_sent = 0L;
            bleStats->bytes_received = 0L;
            bleStats->errors = 0;
            bleStats->active_connections = 0;
            
            // WiFi stats
            auto wifiStats = ProtocolStatDto::createShared();
            wifiStats->protocol = "WiFi";
            wifiStats->packets_sent = 0L;
            wifiStats->packets_received = 0L;
            wifiStats->bytes_sent = 0L;
            wifiStats->bytes_received = 0L;
            wifiStats->errors = 0;
            wifiStats->active_connections = 0;
            
            // LoRa stats
            auto loraStats = ProtocolStatDto::createShared();
            loraStats->protocol = "LoRa";
            loraStats->packets_sent = 0L;
            loraStats->packets_received = 0L;
            loraStats->bytes_sent = 0L;
            loraStats->bytes_received = 0L;
            loraStats->errors = 0;
            loraStats->active_connections = 0;
            
            auto protocols = oatpp::Vector<Object<ProtocolStatDto>>::createShared();
            protocols->push_back(bleStats);
            protocols->push_back(wifiStats);
            protocols->push_back(loraStats);
            
            response->protocols = protocols;
            return createDtoResponseWithCors(Status::CODE_200, response);
        } catch (const std::exception& e) {
            auto error = ErrorDto::createShared();
            error->message = e.what();
            return createDtoResponseWithCors(Status::CODE_500, error);
        }
    }
};

#include OATPP_CODEGEN_END(ApiController)
