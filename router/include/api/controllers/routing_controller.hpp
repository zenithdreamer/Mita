#pragma once

#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/macro/component.hpp"
#include "api/dto.hpp"
#include "services/device_management_service.hpp"

#include OATPP_CODEGEN_BEGIN(ApiController)

/**
 * Routing Controller - Handles routing table and route management endpoints
 */
class RoutingController : public oatpp::web::server::api::ApiController {
private:
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
    RoutingController(const std::shared_ptr<ObjectMapper>& objectMapper)
        : oatpp::web::server::api::ApiController(objectMapper) {}

    static std::shared_ptr<RoutingController> createShared(
        const std::shared_ptr<ObjectMapper>& objectMapper
    ) {
        return std::make_shared<RoutingController>(objectMapper);
    }

    ENDPOINT_INFO(getRoutingTable) {
        info->summary = "Get routing table";
        info->description = "Retrieve the current routing table";
        info->addResponse<Object<RoutingTableDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<ErrorDto>>(Status::CODE_500, "application/json");
        info->addTag("Routing");
    }
    ENDPOINT("GET", "/api/routing-table", getRoutingTable) {
        try {
            auto response = RoutingTableDto::createShared();
            auto routes = oatpp::Vector<Object<RouteDto>>::createShared();
            
            // TODO: Implement actual routing table retrieval
            // For now, return empty routing table
            
            response->routes = routes;
            return createDtoResponse(Status::CODE_200, response);
        } catch (const std::exception& e) {
            auto error = ErrorDto::createShared();
            error->message = e.what();
            return createDtoResponse(Status::CODE_500, error);
        }
    }

    ENDPOINT_INFO(addRoute) {
        info->summary = "Add a route";
        info->description = "Add a new route to the routing table";
        info->addConsumes<Object<RouteDto>>("application/json");
        info->addResponse<Object<SuccessDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<ErrorDto>>(Status::CODE_400, "application/json");
        info->addResponse<Object<ErrorDto>>(Status::CODE_500, "application/json");
        info->addTag("Routing");
    }
    ENDPOINT("POST", "/api/routing-table", addRoute,
             BODY_DTO(Object<RouteDto>, routeDto)) {
        try {
            if (!routeDto->destination || !routeDto->next_hop || 
                !routeDto->metric || !routeDto->interface_type) {
                auto error = ErrorDto::createShared();
                error->message = "Missing required fields";
                return createDtoResponse(Status::CODE_400, error);
            }

            // TODO: Implement actual route addition
            // For now, just return success
            
            auto success = SuccessDto::createShared();
            success->message = "Route added successfully";
            return createDtoResponse(Status::CODE_200, success);
        } catch (const std::exception& e) {
            auto error = ErrorDto::createShared();
            error->message = e.what();
            return createDtoResponse(Status::CODE_500, error);
        }
    }

    ENDPOINT_INFO(deleteRoute) {
        info->summary = "Delete a route";
        info->description = "Remove a route from the routing table";
        info->addResponse<Object<SuccessDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<ErrorDto>>(Status::CODE_404, "application/json");
        info->addResponse<Object<ErrorDto>>(Status::CODE_500, "application/json");
        info->addTag("Routing");
    }
    ENDPOINT("DELETE", "/api/routing-table/{destination}", deleteRoute,
             PATH(String, destination)) {
        try {
            // TODO: Implement actual route deletion
            // For now, just return success
            
            auto success = SuccessDto::createShared();
            success->message = "Route deleted successfully";
            return createDtoResponse(Status::CODE_200, success);
        } catch (const std::exception& e) {
            auto error = ErrorDto::createShared();
            error->message = e.what();
            return createDtoResponse(Status::CODE_500, error);
        }
    }
};

#include OATPP_CODEGEN_END(ApiController)
