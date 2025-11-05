#pragma once

#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/macro/component.hpp"
#include "api/dto.hpp"
#include "services/device_management_service.hpp"
#include "transports/wifi_transport.hpp"
#include "transports/ble/ble_transport.hpp"
#include "transports/ble/ble_device_handler.hpp"

#include OATPP_CODEGEN_BEGIN(ApiController)

/**
 * Devices Controller - Handles device discovery and management endpoints
 */
class DevicesController : public oatpp::web::server::api::ApiController {
private:
    std::shared_ptr<mita::transports::WiFiTransport> m_wifi;
    std::shared_ptr<mita::transports::ble::BLETransport> m_ble;

public:
    DevicesController(const std::shared_ptr<ObjectMapper>& objectMapper,
                     std::shared_ptr<mita::transports::WiFiTransport> wifi = nullptr,
                     std::shared_ptr<mita::transports::ble::BLETransport> ble = nullptr)
        : oatpp::web::server::api::ApiController(objectMapper)
        , m_wifi(wifi)
        , m_ble(ble) {}

    static std::shared_ptr<DevicesController> createShared(
        const std::shared_ptr<ObjectMapper>& objectMapper,
        std::shared_ptr<mita::transports::WiFiTransport> wifi = nullptr,
        std::shared_ptr<mita::transports::ble::BLETransport> ble = nullptr
    ) {
        return std::make_shared<DevicesController>(objectMapper, wifi, ble);
    }

    ENDPOINT_INFO(getWIFIDevices) {
        info->summary = "Get all WIFI devices";
        info->description = "Retrieve list of all discovered devices in the mesh network";
        info->addResponse<Object<DevicesDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<ErrorDto>>(Status::CODE_500, "application/json");
        info->addTag("Devices");
    }
    ENDPOINT("GET", "/api/devices", getWIFIDevices) {
        try {
            auto response = DevicesDto::createShared();
            auto devicesVector = oatpp::Vector<Object<DeviceDto>>::createShared();

            // Get WiFi devices
            if (m_wifi) {
                auto wifi_handlers = m_wifi->get_all_client_handlers();
                for (auto* handler : wifi_handlers) {
                    if (handler) {
                        auto dto = DeviceDto::createShared();
                        dto->device_id = handler->get_device_id();
                        dto->device_type = "wifi";
                        dto->status = handler->is_running() ? "connected" : "disconnected";
                        devicesVector->push_back(dto);
                    }
                }
            }

            response->devices = devicesVector;
            return createDtoResponse(Status::CODE_200, response);
        } catch (const std::exception& e) {
            auto error = ErrorDto::createShared();
            error->message = e.what();
            return createDtoResponse(Status::CODE_500, error);
        }
    }

    ENDPOINT_INFO(getBLEDevices) {
        info->summary = "Get all BLE devices";
        info->description = "Retrieve list of all discovered BLE devices in the mesh network";
        info->addResponse<Object<DevicesDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<ErrorDto>>(Status::CODE_500, "application/json");
        info->addTag("Devices");
    }

    ENDPOINT("GET", "/api/devices/ble", getBLEDevices) {
        try {
            auto response = DevicesDto::createShared();
            auto devicesVector = oatpp::Vector<Object<DeviceDto>>::createShared();

            // Get BLE devices
            if (m_ble) {
                auto ble_handlers = m_ble->get_all_device_handlers();
                for (auto& handler : ble_handlers) {
                    if (handler) {
                        auto dto = DeviceDto::createShared();
                        dto->device_id = handler->get_device_id();
                        dto->device_type = "ble";
                        dto->status = handler->is_connected() ? "connected" : "disconnected";
                        devicesVector->push_back(dto);
                    }
                }
            }

            response->devices = devicesVector;
            return createDtoResponse(Status::CODE_200, response);
        } catch (const std::exception& e) {
            auto error = ErrorDto::createShared();
            error->message = e.what();
            return createDtoResponse(Status::CODE_500, error);
        }
    }

    ENDPOINT_INFO(getDevice) {
        info->summary = "Get device by ID";
        info->description = "Retrieve detailed information about a specific device";
        info->addResponse<Object<DeviceDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<ErrorDto>>(Status::CODE_404, "application/json");
        info->addResponse<Object<ErrorDto>>(Status::CODE_500, "application/json");
        info->addTag("Devices");
    }
    ENDPOINT("GET", "/api/devices/{deviceId}", getDevice,
             PATH(String, deviceId)) {
        try {
            // TODO: Implement actual device retrieval
            auto error = ErrorDto::createShared();
            error->message = "Device not found";
            return createDtoResponse(Status::CODE_404, error);
        } catch (const std::exception& e) {
            auto error = ErrorDto::createShared();
            error->message = e.what();
            return createDtoResponse(Status::CODE_500, error);
        }
    }

    ENDPOINT_INFO(discoverDevices) {
        info->summary = "Discover devices";
        info->description = "Trigger device discovery process to find new devices in the network";
        info->addResponse<Object<SuccessDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<ErrorDto>>(Status::CODE_500, "application/json");
        info->addTag("Devices");
    }
    ENDPOINT("POST", "/api/devices/discover", discoverDevices) {
        try {
            // TODO: Implement actual device discovery
            auto success = SuccessDto::createShared();
            success->message = "Device discovery started";
            return createDtoResponse(Status::CODE_200, success);
        } catch (const std::exception& e) {
            auto error = ErrorDto::createShared();
            error->message = e.what();
            return createDtoResponse(Status::CODE_500, error);
        }
    }
};

#include OATPP_CODEGEN_END(ApiController)
