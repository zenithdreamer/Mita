#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build configuration
BUILD_TYPE=Release
CLEAN_BUILD=false
VERBOSE=false
ENABLE_TESTS=ON

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--clean)
            CLEAN_BUILD=true
            shift
            ;;
        -d|--debug)
            BUILD_TYPE=Debug
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --no-tests)
            ENABLE_TESTS=OFF
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -c, --clean     Clean build directory before building"
            echo "  -d, --debug     Build in Debug mode (default: Release)"
            echo "  -v, --verbose   Verbose build output"
            echo "  --no-tests      Disable building tests"
            echo "  -h, --help      Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}=== Mita Router C++ Build Script ===${NC}"
echo -e "${YELLOW}Build Type: ${BUILD_TYPE}${NC}"
echo -e "${YELLOW}Clean Build: ${CLEAN_BUILD}${NC}"
echo -e "${YELLOW}Build Tests: ${ENABLE_TESTS}${NC}"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"

echo -e "${BLUE}Project Directory: ${PROJECT_DIR}${NC}"
echo -e "${BLUE}Build Directory: ${BUILD_DIR}${NC}"
echo ""

# Clean build directory if requested
if [ "$CLEAN_BUILD" = true ]; then
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    rm -rf "$BUILD_DIR"
fi

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Check for required dependencies
echo -e "${BLUE}Checking dependencies...${NC}"

# Check for required packages
MISSING_DEPS=()

if ! pkg-config --exists dbus-1; then
    MISSING_DEPS+=("libdbus-1-dev")
fi

if ! pkg-config --exists libnm; then
    MISSING_DEPS+=("libnm-dev")
fi

if ! pkg-config --exists bluez; then
    MISSING_DEPS+=("libbluetooth-dev")
fi

if ! pkg-config --exists glib-2.0; then
    MISSING_DEPS+=("libglib2.0-dev")
fi

if ! command -v cmake &> /dev/null; then
    MISSING_DEPS+=("cmake")
fi

if ! dpkg -l | grep -q libssl-dev; then
    MISSING_DEPS+=("libssl-dev")
fi

if ! dpkg -l | grep -q nlohmann-json3-dev; then
    MISSING_DEPS+=("nlohmann-json3-dev")
fi

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    echo -e "${RED}Missing dependencies detected:${NC}"
    for dep in "${MISSING_DEPS[@]}"; do
        echo -e "${RED}  - $dep${NC}"
    done
    echo ""
    echo -e "${YELLOW}Install missing dependencies with:${NC}"
    echo -e "${YELLOW}sudo apt update && sudo apt install ${MISSING_DEPS[*]}${NC}"
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Build cancelled.${NC}"
        exit 1
    fi
fi

# Configure with CMake
echo -e "${BLUE}Configuring with CMake...${NC}"
CMAKE_ARGS=(
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
    -DBUILD_TESTS="$ENABLE_TESTS"
    -DENABLE_WIFI=ON
    -DENABLE_BLE=ON
)

if [ "$VERBOSE" = true ]; then
    CMAKE_ARGS+=(-DCMAKE_VERBOSE_MAKEFILE=ON)
fi

if ! cmake "${CMAKE_ARGS[@]}" "$PROJECT_DIR"; then
    echo -e "${RED}CMake configuration failed!${NC}"
    exit 1
fi

# Build the project
echo -e "${BLUE}Building project...${NC}"
MAKE_ARGS=(-j$(nproc))

if [ "$VERBOSE" = true ]; then
    MAKE_ARGS+=(VERBOSE=1)
fi

if ! make "${MAKE_ARGS[@]}"; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

# Run tests if enabled
if [ "$ENABLE_TESTS" = "ON" ]; then
    echo -e "${BLUE}Running tests...${NC}"
    if ! ctest --output-on-failure; then
        echo -e "${YELLOW}Some tests failed, but build completed successfully.${NC}"
    fi
fi

# Show build results
echo -e "${GREEN}=== Build Completed Successfully! ===${NC}"
echo -e "${GREEN}Executable: ${BUILD_DIR}/mita_router${NC}"

# Show binary information
if [ -f "$BUILD_DIR/mita_router" ]; then
    echo ""
    echo -e "${BLUE}Binary Information:${NC}"
    echo -e "${YELLOW}Size: $(du -h "$BUILD_DIR/mita_router" | cut -f1)${NC}"
    echo -e "${YELLOW}Type: $(file "$BUILD_DIR/mita_router" | cut -d: -f2)${NC}"
    
    # Check if it's executable
    if [ -x "$BUILD_DIR/mita_router" ]; then
        echo -e "${GREEN}Binary is executable${NC}"
        
        # Show help if possible
        echo ""
        echo -e "${BLUE}Usage Information:${NC}"
        "$BUILD_DIR/mita_router" --help || echo -e "${YELLOW}(Help display failed, but binary exists)${NC}"
    else
        echo -e "${RED}Binary is not executable${NC}"
    fi
fi

echo ""
echo -e "${GREEN}Build completed successfully!${NC}"