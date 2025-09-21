# Makefile for Mita Router (C++)
# Alternative to CMake for simple compilation

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -pthread
INCLUDES = -Iinclude -I../shared
DEFINES =

# Build type
BUILD_TYPE ?= release
ifeq ($(BUILD_TYPE),debug)
    CXXFLAGS += -g -O0 -DDEBUG
else
    CXXFLAGS += -O3 -DNDEBUG
endif

# Feature flags
ENABLE_WIFI ?= 1
ENABLE_BLE ?= 1

ifeq ($(ENABLE_WIFI),1)
    DEFINES += -DENABLE_WIFI
endif

ifeq ($(ENABLE_BLE),1)
    DEFINES += -DENABLE_BLE
endif

# Libraries
LIBS = -lssl -lcrypto -lpthread

# Add WiFi libraries if enabled
ifeq ($(ENABLE_WIFI),1)
    LIBS += $(shell pkg-config --libs dbus-1 2>/dev/null || echo "-ldbus-1")
    LIBS += $(shell pkg-config --libs libnm 2>/dev/null || echo "-lnm")
    INCLUDES += $(shell pkg-config --cflags dbus-1 2>/dev/null)
    INCLUDES += $(shell pkg-config --cflags libnm 2>/dev/null)
endif

# Add BLE libraries if enabled
ifeq ($(ENABLE_BLE),1)
    LIBS += $(shell pkg-config --libs bluez 2>/dev/null || echo "-lbluetooth")
    LIBS += $(shell pkg-config --libs glib-2.0 2>/dev/null || echo "-lglib-2.0")
    INCLUDES += $(shell pkg-config --cflags bluez 2>/dev/null)
    INCLUDES += $(shell pkg-config --cflags glib-2.0 2>/dev/null)
endif

# Source files
SRCDIR = src
BUILDDIR = build

# Core sources
CORE_SOURCES = $(wildcard $(SRCDIR)/core/*.cpp)
SERVICE_SOURCES = $(wildcard $(SRCDIR)/services/*.cpp)
PROTOCOL_SOURCES = $(wildcard $(SRCDIR)/protocol/*.cpp)
INFRASTRUCTURE_SOURCES = $(wildcard $(SRCDIR)/infrastructure/*.cpp)

# Transport sources (conditional)
TRANSPORT_SOURCES =
ifeq ($(ENABLE_WIFI),1)
    TRANSPORT_SOURCES += $(wildcard $(SRCDIR)/transports/wifi_*.cpp)
endif
ifeq ($(ENABLE_BLE),1)
    TRANSPORT_SOURCES += $(wildcard $(SRCDIR)/transports/ble_*.cpp)
endif

# All sources
SOURCES = $(SRCDIR)/main.cpp $(CORE_SOURCES) $(SERVICE_SOURCES) $(PROTOCOL_SOURCES) $(INFRASTRUCTURE_SOURCES) $(TRANSPORT_SOURCES)

# Object files
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(BUILDDIR)/%.o)

# Target executable
TARGET = $(BUILDDIR)/mita_router

# Default target
all: $(TARGET)

# Create build directory
$(BUILDDIR):
	@mkdir -p $(BUILDDIR)
	@mkdir -p $(BUILDDIR)/core
	@mkdir -p $(BUILDDIR)/services
	@mkdir -p $(BUILDDIR)/protocol
	@mkdir -p $(BUILDDIR)/infrastructure
	@mkdir -p $(BUILDDIR)/transports

# Build target
$(TARGET): $(BUILDDIR) $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CXX) $(OBJECTS) $(LIBS) -o $(TARGET)
	@echo "Build complete: $(TARGET)"

# Compile source files
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILDDIR)

# Install system-wide
install: $(TARGET)
	@echo "Installing mita_router..."
	sudo cp $(TARGET) /usr/local/bin/
	sudo mkdir -p /etc/mita
	sudo cp config/router_config.json /etc/mita/ 2>/dev/null || true
	sudo mkdir -p /var/log/mita
	@echo "Installation complete"

# Uninstall
uninstall:
	@echo "Uninstalling mita_router..."
	sudo rm -f /usr/local/bin/mita_router
	sudo rm -rf /etc/mita
	sudo rm -rf /var/log/mita
	@echo "Uninstall complete"

# Show help
help:
	@echo "Mita Router Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all (default)  - Build the router"
	@echo "  clean          - Clean build artifacts"
	@echo "  install        - Install system-wide"
	@echo "  uninstall      - Remove system installation"
	@echo "  help           - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  BUILD_TYPE     - release (default) or debug"
	@echo "  ENABLE_WIFI    - 1 (default) or 0"
	@echo "  ENABLE_BLE     - 1 (default) or 0"
	@echo "  CXX            - C++ compiler (default: g++)"
	@echo ""
	@echo "Examples:"
	@echo "  make                          # Build with defaults"
	@echo "  make BUILD_TYPE=debug         # Debug build"
	@echo "  make ENABLE_WIFI=0            # Build without WiFi"
	@echo "  make ENABLE_BLE=0             # Build without BLE"
	@echo "  make clean all                # Clean and rebuild"

# Show build configuration
config:
	@echo "Build Configuration:"
	@echo "  Compiler: $(CXX)"
	@echo "  Build type: $(BUILD_TYPE)"
	@echo "  WiFi support: $(ENABLE_WIFI)"
	@echo "  BLE support: $(ENABLE_BLE)"
	@echo "  C++ flags: $(CXXFLAGS)"
	@echo "  Includes: $(INCLUDES)"
	@echo "  Defines: $(DEFINES)"
	@echo "  Libraries: $(LIBS)"
	@echo "  Sources: $(words $(SOURCES)) files"

# Check dependencies
deps:
	@echo "Checking dependencies..."
	@which $(CXX) >/dev/null || (echo "ERROR: $(CXX) not found" && exit 1)
	@echo "#include <openssl/ssl.h>" | $(CXX) -E - >/dev/null 2>&1 || (echo "ERROR: OpenSSL development headers not found" && exit 1)
	@echo "#include <nlohmann/json.hpp>" | $(CXX) -E - >/dev/null 2>&1 || echo "WARNING: nlohmann-json headers not found"
ifeq ($(ENABLE_WIFI),1)
	@echo "#include <dbus/dbus.h>" | $(CXX) -E - >/dev/null 2>&1 || echo "WARNING: D-Bus development headers not found"
endif
ifeq ($(ENABLE_BLE),1)
	@echo "#include <bluetooth/bluetooth.h>" | $(CXX) -E - >/dev/null 2>&1 || echo "WARNING: BlueZ development headers not found"
endif
	@echo "Dependency check complete"

# Run the router (requires sudo for WiFi AP)
run: $(TARGET)
	sudo $(TARGET) -c config/router_config.json -v

# Run in development mode (no WiFi AP setup)
run-dev: $(TARGET)
	$(TARGET) -c config/router_config.json -D -v

.PHONY: all clean install uninstall help config deps run run-dev