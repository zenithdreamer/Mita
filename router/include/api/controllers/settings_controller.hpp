#pragma once

#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/macro/component.hpp"
#include "api/dto.hpp"
#include "services/settings_service.hpp"

#include OATPP_CODEGEN_BEGIN(ApiController)

// Forward declaration
namespace mita {
namespace core {
class MitaRouter;
}
}

/**
 * Settings Controller - Handles router settings endpoints
 */
class SettingsController : public oatpp::web::server::api::ApiController {
private:
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
        response->putHeader("Connection", "close");
        return response;
    }

public:
    SettingsController(const std::shared_ptr<ObjectMapper>& objectMapper,
                      std::shared_ptr<mita::SettingsService> settingsService = nullptr,
                      mita::core::MitaRouter* router = nullptr)
        : oatpp::web::server::api::ApiController(objectMapper)
        , m_settingsService(settingsService)
        , m_router(router) {}

    static std::shared_ptr<SettingsController> createShared(
        const std::shared_ptr<ObjectMapper>& objectMapper,
        std::shared_ptr<mita::SettingsService> settingsService = nullptr,
        mita::core::MitaRouter* router = nullptr
    ) {
        return std::make_shared<SettingsController>(objectMapper, settingsService, router);
    }

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

    ENDPOINT_INFO(updateSettings) {
        info->summary = "Update transport settings";
        info->description = "Enable or disable transports (WiFi, BLE, Zigbee) and apply changes immediately";
        info->addResponse<Object<SettingsDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<StatusDto>>(Status::CODE_500, "application/json");
        info->addTag("Settings");
    }
    ENDPOINT("PUT", "/api/settings", updateSettings,
             BODY_DTO(Object<SettingsDto>, body)) {
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
};

#include OATPP_CODEGEN_END(ApiController)
