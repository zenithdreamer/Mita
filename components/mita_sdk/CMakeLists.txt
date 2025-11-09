# Mita SDK Component - Pure Library (No app_main)

# Gather all SDK source files
file(GLOB_RECURSE SDK_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.c"
)

# Gather shared protocol/crypto sources
file(GLOB_RECURSE SHARED_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/../../shared/**/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../shared/**/*.c"
)

# ArduinoJson path (from PlatformIO lib_deps)
set(ARDUINOJSON_DIR "${CMAKE_SOURCE_DIR}/.pio/libdeps/esp32dev/ArduinoJson/src")

idf_component_register(
    SRCS
        ${SDK_SOURCES}
        ${SHARED_SOURCES}
    INCLUDE_DIRS
        "."
        "../../include"
        "../../shared"
    PRIV_INCLUDE_DIRS
        "${ARDUINOJSON_DIR}"
    REQUIRES
        nvs_flash
        esp_wifi
        esp_netif
        lwip
        bt
        mbedtls
        json
        driver
)
