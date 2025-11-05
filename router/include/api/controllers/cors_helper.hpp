#pragma once

#include "oatpp/web/server/api/ApiController.hpp"

/**
 * CORS Helper Mixin
 * Add this as a template base class to any controller that needs CORS support
 */
template<typename T>
class CorsHelper {
protected:
    // Helper to add CORS headers to any response
    template<class DtoType>
    std::shared_ptr<typename T::OutgoingResponse> createDtoResponseWithCors(
        const typename T::Status& status, 
        const DtoType& dto,
        T* controller) 
    {
        auto response = controller->createDtoResponse(status, dto);
        response->putHeader("Access-Control-Allow-Origin", "http://localhost:5173");
        response->putHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        response->putHeader("Access-Control-Allow-Headers", "Content-Type, Cookie");
        response->putHeader("Access-Control-Allow-Credentials", "true");
        response->putHeader("Connection", "close");
        return response;
    }
};
