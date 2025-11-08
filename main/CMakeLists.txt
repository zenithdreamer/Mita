# Gather all source files automatically
file(GLOB_RECURSE MAIN_SOURCES 
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.c"
)

file(GLOB_RECURSE SHARED_SOURCES 
    "${CMAKE_CURRENT_SOURCE_DIR}/../shared/**/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../shared/**/*.c"
)

idf_component_register(
    SRCS 
        ${MAIN_SOURCES}
        ${SHARED_SOURCES}
    INCLUDE_DIRS 
        "."
        "../include"
        "../shared"
    REQUIRES 
        nvs_flash 
        esp_wifi 
        esp_netif
        lwip
        bt
        mbedtls
        json
)
