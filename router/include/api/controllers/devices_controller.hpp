#pragma once

#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/macro/component.hpp"
#include "api/dto.hpp"
#include "services/device_management_service.hpp"

#include OATPP_CODEGEN_BEGIN(ApiController)

/**
 * Devices Controller - Handles device discovery and management endpoints
 */
class DevicesController : public oatpp::web::server::api::ApiController {
public:
    DevicesController(const std::shared_ptr<ObjectMapper>& objectMapper)
        : oatpp::web::server::api::ApiController(objectMapper) {}

    static std::shared_ptr<DevicesController> createShared(
        const std::shared_ptr<ObjectMapper>& objectMapper
    ) {
        return std::make_shared<DevicesController>(objectMapper);
    }

    ENDPOINT_INFO(getDevices) {
        info->summary = "Get all devices";
        info->description = "Retrieve list of all discovered devices in the mesh network";
        info->addResponse<Object<DevicesDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<ErrorDto>>(Status::CODE_500, "application/json");
        info->addTag("Devices");
    }
    ENDPOINT("GET", "/api/devices", getDevices) {
        try {
            // TODO: Implement actual device list retrieval
            // For now, return empty device list
            
            auto response = DevicesDto::createShared();
            auto devicesVector = oatpp::Vector<Object<DeviceDto>>::createShared();
            
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
