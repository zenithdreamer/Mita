#pragma once

#include "oatpp/web/server/interceptor/RequestInterceptor.hpp"
#include "oatpp/web/protocol/http/Http.hpp"
#include "oatpp/web/protocol/http/outgoing/ResponseFactory.hpp"
#include "services/auth_service.hpp"
#include <memory>
#include <string>
#include <vector>

class AuthInterceptor : public oatpp::web::server::interceptor::RequestInterceptor {
private:
  std::shared_ptr<mita::AuthService> m_authService;
  std::vector<std::string> m_publicPaths;

  // Helper to extract session token from cookies
  std::string getSessionTokenFromCookies(const std::shared_ptr<oatpp::web::protocol::http::incoming::Request>& request) {
    auto cookieHeader = request->getHeader("Cookie");
    if (!cookieHeader) {
      return "";
    }

    std::string cookies = cookieHeader->c_str();
    std::string sessionPrefix = "session_token=";
    size_t pos = cookies.find(sessionPrefix);

    if (pos == std::string::npos) {
      return "";
    }

    size_t start = pos + sessionPrefix.length();
    size_t end = cookies.find(";", start);

    if (end == std::string::npos) {
      return cookies.substr(start);
    }

    return cookies.substr(start, end - start);
  }

  bool isPublicPath(const std::string& path) {
    for (const auto& publicPath : m_publicPaths) {
      if (path.find(publicPath) == 0) {
        return true;
      }
    }
    return false;
  }

public:
  explicit AuthInterceptor(std::shared_ptr<mita::AuthService> authService)
    : m_authService(authService) {
    // Define public paths that don't require authentication
    m_publicPaths = {
      "/api/auth/login",
      "/swagger",
      "/api-docs",
      "/favicon.ico"
    };
  }

  std::shared_ptr<OutgoingResponse> intercept(const std::shared_ptr<IncomingRequest>& request) override {
    auto path = request->getStartingLine().path.toString();

    // Allow OPTIONS requests (CORS preflight)
    if (request->getStartingLine().method == "OPTIONS") {
      return nullptr; // Continue to the handler
    }

    // Check if path is public
    if (isPublicPath(path->c_str())) {
      return nullptr; // Continue to the handler
    }

    // Get session token from cookies
    std::string sessionToken = getSessionTokenFromCookies(request);

    if (sessionToken.empty()) {
      printf("[AUTH] No session token found - access denied\n");
      fflush(stdout);

      auto response = oatpp::web::protocol::http::outgoing::ResponseFactory::createResponse(
        oatpp::web::protocol::http::Status::CODE_401,
        R"({"status":"error","message":"Authentication required"})"
      );

      response->putHeader("Content-Type", "application/json");
      response->putHeader("Access-Control-Allow-Origin", "http://localhost:5173");
      response->putHeader("Access-Control-Allow-Credentials", "true");
      response->putHeader("Connection", "close");

      return response;
    }

    // Validate session
    auto validateResult = m_authService->validateSession(sessionToken);

    if (!validateResult.valid) {
      printf("[AUTH] Invalid or expired session token - access denied\n");
      fflush(stdout);

      auto response = oatpp::web::protocol::http::outgoing::ResponseFactory::createResponse(
        oatpp::web::protocol::http::Status::CODE_401,
        R"({"status":"error","message":"Invalid or expired session"})"
      );

      response->putHeader("Content-Type", "application/json");
      response->putHeader("Access-Control-Allow-Origin", "http://localhost:5173");
      response->putHeader("Access-Control-Allow-Credentials", "true");
      response->putHeader("Connection", "close");

      return response;
    }

    // Continue to the handler
    return nullptr;
  }
};
