#pragma once

#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/macro/component.hpp"
#include "api/dto.hpp"
#include "services/auth_service.hpp"
#include <memory>

#include OATPP_CODEGEN_BEGIN(ApiController)

class AuthController : public oatpp::web::server::api::ApiController {
private:
  std::shared_ptr<mita::AuthService> m_authService;

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

  // Helper to extract session token from cookies
  std::string getSessionTokenFromCookies(const std::shared_ptr<IncomingRequest>& request) {
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

public:
  AuthController(const std::shared_ptr<ObjectMapper>& objectMapper,
                 std::shared_ptr<mita::AuthService> authService)
    : oatpp::web::server::api::ApiController(objectMapper)
    , m_authService(authService)
  {}

  // POST /api/auth/login
  ENDPOINT_INFO(login) {
    info->summary = "Login to the router";
    info->description = "Authenticate user with username and password";
    info->addConsumes<Object<LoginRequestDto>>("application/json");
    info->addResponse<Object<LoginResponseDto>>(Status::CODE_200, "application/json");
    info->addResponse<Object<LoginResponseDto>>(Status::CODE_401, "application/json");
    info->addTag("Authentication");
  }
  ENDPOINT("POST", "/api/auth/login", login,
           BODY_DTO(Object<LoginRequestDto>, loginDto)) {

    printf("[AUTH] POST /api/auth/login - login attempt for user: %s\n",
           loginDto->username->c_str());
    fflush(stdout);

    auto dto = LoginResponseDto::createShared();

    // Validate input
    if (!loginDto->username || !loginDto->password) {
      dto->success = false;
      dto->message = "Username and password are required";
      return createDtoResponseWithCors(Status::CODE_400, dto);
    }

    // Authenticate
    auto result = m_authService->authenticate(
      loginDto->username->c_str(),
      loginDto->password->c_str()
    );

    dto->success = result.success;
    dto->message = result.message;

    if (result.success) {
      dto->username = loginDto->username;
      dto->userId = result.userId;

      // Set session cookie
      auto response = createDtoResponseWithCors(Status::CODE_200, dto);

      // Create cookie with session token
      // For localhost development with different ports (cross-origin), use SameSite=Lax
      // SameSite=Lax allows cookies to be sent with top-level navigations and same-site requests
      std::string cookieValue = "session_token=" + result.sessionToken +
                                "; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax";

      response->putHeader("Set-Cookie", cookieValue);

      printf("[AUTH] Login successful for user: %s\n", loginDto->username->c_str());
      fflush(stdout);

      return response;
    } else {
      printf("[AUTH] Login failed for user: %s - %s\n",
             loginDto->username->c_str(), result.message.c_str());
      fflush(stdout);

      return createDtoResponseWithCors(Status::CODE_401, dto);
    }
  }

  // POST /api/auth/logout
  ENDPOINT_INFO(logout) {
    info->summary = "Logout from the router";
    info->description = "Invalidate current session";
    info->addResponse<Object<StatusDto>>(Status::CODE_200, "application/json");
    info->addTag("Authentication");
  }
  ENDPOINT("POST", "/api/auth/logout", logout,
           REQUEST(std::shared_ptr<IncomingRequest>, request)) {

    printf("[AUTH] POST /api/auth/logout - logout request\n");
    fflush(stdout);

    auto dto = StatusDto::createShared();

    // Get session token from cookies
    std::string sessionToken = getSessionTokenFromCookies(request);

    if (!sessionToken.empty()) {
      m_authService->logout(sessionToken);
    }

    dto->status = "success";
    dto->message = "Logged out successfully";
    dto->uptime = 0L;

    // Clear cookie
    auto response = createDtoResponseWithCors(Status::CODE_200, dto);
    response->putHeader("Set-Cookie", "session_token=; Path=/; HttpOnly; Max-Age=0");

    printf("[AUTH] Logout successful\n");
    fflush(stdout);

    return response;
  }

  // GET /api/auth/me
  ENDPOINT_INFO(getCurrentUser) {
    info->summary = "Get current user info";
    info->description = "Returns information about the currently authenticated user";
    info->addResponse<Object<UserInfoDto>>(Status::CODE_200, "application/json");
    info->addResponse<Object<StatusDto>>(Status::CODE_401, "application/json");
    info->addTag("Authentication");
  }
  ENDPOINT("GET", "/api/auth/me", getCurrentUser,
           REQUEST(std::shared_ptr<IncomingRequest>, request)) {

    // Get session token from cookies
    std::string sessionToken = getSessionTokenFromCookies(request);

    if (sessionToken.empty()) {
      auto errorDto = StatusDto::createShared();
      errorDto->status = "error";
      errorDto->message = "Not authenticated";
      errorDto->uptime = 0L;
      return createDtoResponseWithCors(Status::CODE_401, errorDto);
    }

    // Validate session
    auto validateResult = m_authService->validateSession(sessionToken);

    if (!validateResult.valid) {
      auto errorDto = StatusDto::createShared();
      errorDto->status = "error";
      errorDto->message = "Invalid or expired session";
      errorDto->uptime = 0L;
      return createDtoResponseWithCors(Status::CODE_401, errorDto);
    }

    // User info is already in validateResult
    auto dto = UserInfoDto::createShared();
    dto->id = validateResult.userId;
    dto->username = validateResult.username;
    dto->createdAt = 0L; // Note: createdAt not available in session, would need separate query

    printf("[AUTH] Current user: %s (ID: %ld)\n", validateResult.username.c_str(), validateResult.userId);
    fflush(stdout);

    return createDtoResponseWithCors(Status::CODE_200, dto);
  }
};

#include OATPP_CODEGEN_END(ApiController)
