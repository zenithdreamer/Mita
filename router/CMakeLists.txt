cmake_minimum_required(VERSION 3.16)
project(MitaRouter VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build configuration
set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type")
option(BUILD_TESTS "Build tests" ON)
# Always enable WiFi and BLE; SimpleBluez mandatory
set(ENABLE_WIFI ON)
set(ENABLE_BLE ON)
set(USE_SIMPLEBLUEZ ON)

# Platform-specific settings for Raspberry Pi
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "armv7l")
    set(RASPBERRY_PI TRUE)
    message(STATUS "Building for Raspberry Pi")
endif()

# Include directories
include_directories(include)
include_directories(../shared)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# JSON library for configuration
find_package(nlohmann_json REQUIRED)

# OpenSSL for cryptography
find_package(OpenSSL REQUIRED)

# DBus for NetworkManager integration (WiFi)
pkg_check_modules(DBUS REQUIRED dbus-1)
pkg_check_modules(NM REQUIRED libnm)

# BlueZ for BLE support
# Raw BlueZ / GLib path deprecated; SimpleBluez handles BlueZ internally

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Source files
file(GLOB_RECURSE CORE_SOURCES "src/core/*.cpp")
file(GLOB_RECURSE SERVICE_SOURCES "src/services/*.cpp")
file(GLOB_RECURSE INFRASTRUCTURE_SOURCES "src/infrastructure/*.cpp")
file(GLOB_RECURSE PROTOCOL_SOURCES "src/protocol/*.cpp")

# Transport sources (conditional)
set(TRANSPORT_SOURCES "")
file(GLOB WIFI_SOURCES "src/transports/wifi_*.cpp")
list(APPEND TRANSPORT_SOURCES ${WIFI_SOURCES})
# New BLE sources from ble/ subdirectory
file(GLOB_RECURSE BLE_SOURCES "src/transports/ble/*.cpp")
list(APPEND TRANSPORT_SOURCES ${BLE_SOURCES})
add_definitions(-DUSE_SIMPLEBLUEZ)

# Fetch SimpleBLE
include(FetchContent)
FetchContent_Declare(simpleble
    GIT_REPOSITORY https://github.com/OpenBluetoothToolbox/SimpleBLE.git
    GIT_TAG v0.10.3
    SOURCE_SUBDIR simpleble
)
FetchContent_MakeAvailable(simpleble)

# Main executable
add_executable(mita_router
    src/main.cpp
    ${CORE_SOURCES}
    ${SERVICE_SOURCES}
    ${TRANSPORT_SOURCES}
    ${INFRASTRUCTURE_SOURCES}
    ${PROTOCOL_SOURCES}
)

# Provide fmt dependency if not already available (SimpleBluez / SimpleDBus requires <fmt/core.h>)
if(NOT TARGET fmt::fmt)
    message(STATUS "Fetching fmt library (header-only)")
    FetchContent_Declare(fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt.git
        GIT_TAG 11.0.2
    )
    FetchContent_MakeAvailable(fmt)
endif()

# Link libraries
target_link_libraries(mita_router
    Threads::Threads
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
    fmt::fmt
)

# WiFi-specific libraries
target_link_libraries(mita_router ${DBUS_LIBRARIES} ${NM_LIBRARIES})
target_include_directories(mita_router PRIVATE ${DBUS_INCLUDE_DIRS} ${NM_INCLUDE_DIRS})
target_compile_definitions(mita_router PRIVATE ENABLE_WIFI)

# BLE-specific libraries
target_link_libraries(mita_router simpleble)

target_compile_definitions(mita_router PRIVATE ENABLE_BLE USE_SIMPLEBLUEZ)

# Install targets
install(TARGETS mita_router DESTINATION bin)
install(FILES config/router_config.json DESTINATION etc/mita)

# Systemd service (optional)
if(EXISTS "/lib/systemd/system")
    install(FILES scripts/mita-router.service DESTINATION /lib/systemd/system)
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
        add_subdirectory(tests)
    else()
        message(STATUS "Tests directory exists but no CMakeLists.txt found - skipping tests")
    endif()
endif()

# Print configuration summary
message(STATUS "=== Mita Router Configuration ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "WiFi transport: ON (forced)")
message(STATUS "BLE transport: ON (forced, SimpleBluez)")
message(STATUS "Use SimpleBluez: ON (mandatory)")
message(STATUS "Raspberry Pi: ${RASPBERRY_PI}")
message(STATUS "Build tests: ${BUILD_TESTS}")