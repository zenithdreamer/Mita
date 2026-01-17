cmake_minimum_required(VERSION 3.16)
project(MitaRouter VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build configuration
set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type")
option(BUILD_TESTS "Build tests" ON)

# Always enable WiFi, BLE, and LoRa
set(ENABLE_WIFI ON)
set(ENABLE_BLE ON)
set(ENABLE_LORA ON)

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

# SQLite3 for database
find_package(SQLite3 REQUIRED)

# DBus for NetworkManager integration (WiFi)
pkg_check_modules(DBUS REQUIRED dbus-1)
pkg_check_modules(NM REQUIRED libnm)

# BlueZ for BLE support
# Raw BlueZ / GLib path deprecated; SimpleBluez handles BlueZ internally

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Suppress warnings from system headers and dependencies
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter -Wno-sign-compare -Wno-catch-value -Wno-missing-field-initializers -Wno-sequence-point")

# Source files
file(GLOB_RECURSE CORE_SOURCES "src/core/*.cpp")
file(GLOB_RECURSE SERVICE_SOURCES "src/services/*.cpp")
file(GLOB_RECURSE INFRASTRUCTURE_SOURCES "src/infrastructure/*.cpp")
file(GLOB_RECURSE PROTOCOL_SOURCES "src/protocol/*.cpp")

# Shared crypto sources (for router)
file(GLOB SHARED_CRYPTO_SOURCES "../shared/crypto/*.cpp")

# Transport sources (conditional)
set(TRANSPORT_SOURCES "")
file(GLOB WIFI_SOURCES "src/transports/wifi_*.cpp")
list(APPEND TRANSPORT_SOURCES ${WIFI_SOURCES})
# New BLE sources from ble/ subdirectory
file(GLOB_RECURSE BLE_SOURCES "src/transports/ble/*.cpp")
list(APPEND TRANSPORT_SOURCES ${BLE_SOURCES})

file(GLOB_RECURSE LORA_SOURCES "src/transports/lora/*.cpp")
list(APPEND TRANSPORT_SOURCES ${LORA_SOURCES})

# Fetch sqlite_orm (header-only ORM library)
include(FetchContent)
FetchContent_Declare(sqlite_orm
    GIT_REPOSITORY https://github.com/fnc12/sqlite_orm.git
    GIT_TAG v1.9
)
FetchContent_MakeAvailable(sqlite_orm)

# Disable oatpp tests to speed up build
option(OATPP_BUILD_TESTS "Build oatpp tests" OFF)

# Force oatpp modules to use CUSTOM location (not INSTALLED)
# This prevents oatpp-swagger from trying to find_package(oatpp)
set(OATPP_MODULES_LOCATION "CUSTOM" CACHE STRING "" FORCE)

# Fetch oatpp
FetchContent_Declare(
    oatpp
    GIT_REPOSITORY https://github.com/oatpp/oatpp.git
    GIT_TAG 1.3.0
)

# Make oatpp available first
FetchContent_MakeAvailable(oatpp)

# Suppress warnings from oatpp
if(TARGET oatpp)
    target_compile_options(oatpp PRIVATE -w)
endif()

# Set paths for CUSTOM mode - tell oatpp-swagger where to find oatpp
set(OATPP_DIR_SRC "${oatpp_SOURCE_DIR}/src" CACHE STRING "" FORCE)
set(OATPP_DIR_LIB "${oatpp_BINARY_DIR}/src" CACHE STRING "" FORCE)

# Fetch oatpp-swagger (depends on oatpp being available)
FetchContent_Declare(
    oatpp-swagger
    GIT_REPOSITORY https://github.com/oatpp/oatpp-swagger.git
    GIT_TAG 1.3.0
)

# Make oatpp-swagger available after oatpp is ready
FetchContent_MakeAvailable(oatpp-swagger)

# Suppress warnings from oatpp-swagger
if(TARGET oatpp-swagger)
    target_compile_options(oatpp-swagger PRIVATE -w)
endif()

# Define swagger resource path
add_definitions(-DOATPP_SWAGGER_RES_PATH="${oatpp-swagger_SOURCE_DIR}/res")

# Fetch RadioLib for LoRa support
message(STATUS "Fetching RadioLib for LoRa support")
FetchContent_Declare(
    RadioLib
    GIT_REPOSITORY https://github.com/jgromes/RadioLib.git
    GIT_TAG 6.6.0
)

set(RADIOLIB_STATIC ON CACHE BOOL "" FORCE)
set(RADIOLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(RADIOLIB_PLATFORM "Generic" CACHE STRING "" FORCE)

FetchContent_MakeAvailable(RadioLib)

if(TARGET RadioLib)
    target_compile_options(RadioLib PRIVATE -w)
endif()

# Find lgpio library for Raspberry Pi GPIO/SPI access
find_library(LGPIO_LIBRARY lgpio)
if(NOT LGPIO_LIBRARY)
    message(FATAL_ERROR "lgpio library not found. Install with: sudo apt install liblgpio-dev")
endif()

# Main executable
add_executable(mita_router
    src/main.cpp
    ${CORE_SOURCES}
    ${SERVICE_SOURCES}
    ${TRANSPORT_SOURCES}
    ${INFRASTRUCTURE_SOURCES}
    ${PROTOCOL_SOURCES}
    ${SHARED_CRYPTO_SOURCES}
)

# Provide fmt dependency if not already available (SimpleBluez / SimpleDBus requires <fmt/core.h>)
if(NOT TARGET fmt::fmt)
    message(STATUS "Fetching fmt library (header-only)")
    FetchContent_Declare(fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt.git
        GIT_TAG 11.0.2
    )
    FetchContent_MakeAvailable(fmt)

    # Suppress warnings from fmt
    if(TARGET fmt)
        target_compile_options(fmt PRIVATE -w)
    endif()
endif()

# Mark sqlite_orm include directories as SYSTEM to suppress warnings from the library
get_target_property(SQLITE_ORM_INCLUDE_DIRS sqlite_orm::sqlite_orm INTERFACE_INCLUDE_DIRECTORIES)
if(SQLITE_ORM_INCLUDE_DIRS)
    target_include_directories(mita_router SYSTEM PRIVATE ${SQLITE_ORM_INCLUDE_DIRS})
endif()

# Link libraries
target_link_libraries(mita_router
    Threads::Threads
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite::SQLite3
    fmt::fmt
    sqlite_orm::sqlite_orm
    oatpp
    oatpp-swagger
)

# WiFi-specific libraries
target_link_libraries(mita_router ${DBUS_LIBRARIES} ${NM_LIBRARIES})
target_include_directories(mita_router PRIVATE ${DBUS_INCLUDE_DIRS} ${NM_INCLUDE_DIRS})
target_compile_definitions(mita_router PRIVATE ENABLE_WIFI)

# BLE-specific libraries
target_link_libraries(mita_router bluetooth)

target_compile_definitions(mita_router PRIVATE ENABLE_BLE)

# LoRa-specific libraries (RadioLib + lgpio for Raspberry Pi)
target_link_libraries(mita_router RadioLib ${LGPIO_LIBRARY})
target_include_directories(mita_router PRIVATE ${RadioLib_SOURCE_DIR}/src)
target_compile_definitions(mita_router PRIVATE ENABLE_LORA)

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
message(STATUS "BLE transport: ON (L2CAP)")
message(STATUS "LoRa transport: ON")
message(STATUS "Raspberry Pi: ${RASPBERRY_PI}")
message(STATUS "Build tests: ${BUILD_TESTS}")
