#!/bin/bash
# Build script for Mita Router

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building Mita Router with HTTP API...${NC}"

# Build directory
BUILD_DIR="build"
BUILD_TYPE="${1:-Release}"

# Check for clean flag
if [ "$1" == "clean" ] || [ "$2" == "clean" ]; then
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    rm -rf "$BUILD_DIR"
fi

# Create build directory
if [ ! -d "$BUILD_DIR" ]; then
    echo -e "${YELLOW}Creating build directory...${NC}"
    mkdir -p "$BUILD_DIR"
fi

cd "$BUILD_DIR"

# Run CMake
echo -e "${YELLOW}Running CMake...${NC}"
cmake -DCMAKE_BUILD_TYPE="$BUILD_TYPE" ..

# Build
echo -e "${YELLOW}Building...${NC}"
if ! make -j$(nproc); then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Build complete!${NC}"
echo -e "Executable: ${YELLOW}$BUILD_DIR/mita_router${NC}"
echo ""
echo "To run:"
echo "  ./run.sh         # Run (dev mode without sudo, full mode with sudo)"
echo "  sudo ./run.sh    # Run with WiFi AP support"
echo ""
echo "To clean build:"
echo "  ./build.sh clean # Remove build directory and rebuild from scratch"
