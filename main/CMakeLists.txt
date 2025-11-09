# Main application entry point
# SDK is now a separate component in components/mita_sdk/

# Select which demo to build based on CMake defines from platformio.ini
if(DEMO_BIDIRECTIONAL)
    set(MAIN_SOURCE "demo_bidirectional.cpp")
    message(STATUS "Building DEMO_BIDIRECTIONAL")
elseif(DEMO_CONTROLLER)
    set(MAIN_SOURCE "demo_controller.cpp")
    message(STATUS "Building DEMO_CONTROLLER (legacy)")
elseif(DEMO_LED)
    set(MAIN_SOURCE "demo_led.cpp")
    message(STATUS "Building DEMO_LED (legacy)")
else()
    set(MAIN_SOURCE "main.cpp")
    message(STATUS "Building default main.cpp")
endif()

idf_component_register(
    SRCS
        "${MAIN_SOURCE}"
    INCLUDE_DIRS
        "."
        "../include"
    REQUIRES
        nvs_flash
        mita_sdk
        driver
)
