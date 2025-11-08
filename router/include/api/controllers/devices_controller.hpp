#pragma once

#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/macro/component.hpp"
#include "api/dto.hpp"
#include "services/device_management_service.hpp"
#include "transports/wifi_transport.hpp"
#include "transports/ble/ble_transport.hpp"
#include <chrono>
#include <sstream>
#include <iomanip>

#include OATPP_CODEGEN_BEGIN(ApiController)

/**
 * Devices Controller - Handles device discovery and management endpoints
 */
class DevicesController : public oatpp::web::server::api::ApiController {
private:
    std::shared_ptr<mita::transports::WiFiTransport> m_wifi;
    std::shared_ptr<mita::transports::ble::BLETransport> m_ble;
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
    DevicesController(const std::shared_ptr<ObjectMapper>& objectMapper,
                     std::shared_ptr<mita::transports::WiFiTransport> wifi = nullptr,
                     std::shared_ptr<mita::transports::ble::BLETransport> ble = nullptr,
                     std::shared_ptr<mita::services::DeviceManagementService> deviceManager = nullptr)
        : oatpp::web::server::api::ApiController(objectMapper)
        , m_wifi(wifi)
        , m_ble(ble)
        , m_deviceManager(deviceManager) {}

    static std::shared_ptr<DevicesController> createShared(
        const std::shared_ptr<ObjectMapper>& objectMapper,
        std::shared_ptr<mita::transports::WiFiTransport> wifi = nullptr,
        std::shared_ptr<mita::transports::ble::BLETransport> ble = nullptr,
        std::shared_ptr<mita::services::DeviceManagementService> deviceManager = nullptr
    ) {
        return std::make_shared<DevicesController>(objectMapper, wifi, ble, deviceManager);
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

            // Get devices from device management service if available
            if (m_deviceManager) {
                auto deviceList = m_deviceManager->get_device_list();
                auto now = std::chrono::steady_clock::now();
                
                for (const auto& [device_id, device] : deviceList) {
                    // Only include WiFi devices
                    if (device.transport_type == mita::core::TransportType::WIFI) {
                        auto dto = DeviceDto::createShared();
                        dto->device_id = device_id;
                        dto->device_type = "wifi";
                        
                        // Map device state to status string
                        switch (device.state) {
                            case mita::services::DeviceState::CONNECTING:
                                dto->status = "connecting";
                                break;
                            case mita::services::DeviceState::HANDSHAKING:
                                dto->status = "handshaking";
                                break;
                            case mita::services::DeviceState::AUTHENTICATED:
                                dto->status = "authenticated";
                                break;
                            case mita::services::DeviceState::ACTIVE:
                                dto->status = "active";
                                break;
                            case mita::services::DeviceState::DISCONNECTING:
                                dto->status = "disconnecting";
                                break;
                            case mita::services::DeviceState::ERROR:
                                dto->status = "error";
                                break;
                            default:
                                dto->status = "unknown";
                                break;
                        }
                        
                        // Calculate Unix timestamp for last_seen
                        // We need to convert from steady_clock to system_clock (Unix time)
                        auto now_steady = std::chrono::steady_clock::now();
                        auto now_system = std::chrono::system_clock::now();
                        auto time_since_activity = now_steady - device.last_activity;
                        auto last_seen_time = now_system - time_since_activity;
                        auto last_seen_unix = std::chrono::duration_cast<std::chrono::seconds>(
                            last_seen_time.time_since_epoch()
                        );
                        dto->last_seen = last_seen_unix.count();
                        
                        // Set address
                        std::stringstream addr_ss;
                        addr_ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << device.assigned_address;
                        dto->address = addr_ss.str();
                        
                        // Set transport
                        dto->transport = "wifi";
                        
                        // Convert connected_time to Unix timestamp
                        auto connected_duration = std::chrono::duration_cast<std::chrono::seconds>(
                            device.connected_time.time_since_epoch()
                        );
                        dto->connected_time = connected_duration.count();
                        
                        // Calculate connection duration
                        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                            now - device.connected_time
                        );
                        dto->connection_duration = duration.count();
                        
                        // Default values for optional fields
                        dto->rssi = 0;
                        dto->battery_level = 0;
                        
                        devicesVector->push_back(dto);
                    }
                }
            }

            response->devices = devicesVector;
            return createDtoResponseWithCors(Status::CODE_200, response);
        } catch (const std::exception& e) {
            auto error = ErrorDto::createShared();
            error->message = e.what();
            return createDtoResponseWithCors(Status::CODE_500, error);
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

            // Get devices from device management service if available
            if (m_deviceManager) {
                auto deviceList = m_deviceManager->get_device_list();
                auto now = std::chrono::steady_clock::now();
                
                for (const auto& [device_id, device] : deviceList) {
                    // Only include BLE devices
                    if (device.transport_type == mita::core::TransportType::BLE) {
                        auto dto = DeviceDto::createShared();
                        dto->device_id = device_id;
                        dto->device_type = "ble";
                        
                        // Map device state to status string
                        switch (device.state) {
                            case mita::services::DeviceState::CONNECTING:
                                dto->status = "connecting";
                                break;
                            case mita::services::DeviceState::HANDSHAKING:
                                dto->status = "handshaking";
                                break;
                            case mita::services::DeviceState::AUTHENTICATED:
                                dto->status = "authenticated";
                                break;
                            case mita::services::DeviceState::ACTIVE:
                                dto->status = "active";
                                break;
                            case mita::services::DeviceState::DISCONNECTING:
                                dto->status = "disconnecting";
                                break;
                            case mita::services::DeviceState::ERROR:
                                dto->status = "error";
                                break;
                            default:
                                dto->status = "unknown";
                                break;
                        }
                        
                        // Calculate Unix timestamp for last_seen
                        // We need to convert from steady_clock to system_clock (Unix time)
                        auto now_steady = std::chrono::steady_clock::now();
                        auto now_system = std::chrono::system_clock::now();
                        auto time_since_activity = now_steady - device.last_activity;
                        auto last_seen_time = now_system - time_since_activity;
                        auto last_seen_unix = std::chrono::duration_cast<std::chrono::seconds>(
                            last_seen_time.time_since_epoch()
                        );
                        dto->last_seen = last_seen_unix.count();
                        
                        // Set address
                        std::stringstream addr_ss;
                        addr_ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << device.assigned_address;
                        dto->address = addr_ss.str();
                        
                        // Set transport
                        dto->transport = "ble";
                        
                        // Convert connected_time to Unix timestamp
                        auto connected_duration = std::chrono::duration_cast<std::chrono::seconds>(
                            device.connected_time.time_since_epoch()
                        );
                        dto->connected_time = connected_duration.count();
                        
                        // Calculate connection duration
                        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                            now - device.connected_time
                        );
                        dto->connection_duration = duration.count();
                        
                        // Default values for optional fields
                        dto->rssi = 0;
                        dto->battery_level = 0;
                        
                        devicesVector->push_back(dto);
                    }
                }
            }

            response->devices = devicesVector;
            return createDtoResponseWithCors(Status::CODE_200, response);
        } catch (const std::exception& e) {
            auto error = ErrorDto::createShared();
            error->message = e.what();
            return createDtoResponseWithCors(Status::CODE_500, error);
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
            return createDtoResponseWithCors(Status::CODE_404, error);
        } catch (const std::exception& e) {
            auto error = ErrorDto::createShared();
            error->message = e.what();
            return createDtoResponseWithCors(Status::CODE_500, error);
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
            return createDtoResponseWithCors(Status::CODE_200, success);
        } catch (const std::exception& e) {
            auto error = ErrorDto::createShared();
            error->message = e.what();
            return createDtoResponseWithCors(Status::CODE_500, error);
        }
    }
};

#include OATPP_CODEGEN_END(ApiController)
