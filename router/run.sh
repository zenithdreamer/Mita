#!/bin/bash
# Run script for Mita Router

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if built
if [ ! -f "build/mita_router" ]; then
    echo -e "${RED}Error: mita_router not built${NC}"
    echo -e "Run: ${YELLOW}./build.sh${NC} first"
    exit 1
fi

# Check for sudo and set flags accordingly
DEV_MODE_FLAG=""
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Warning: Not running as sudo${NC}"
    echo -e "${YELLOW}WiFi AP setup will be skipped (dev mode)${NC}"
    echo ""
    DEV_MODE_FLAG="-D"
fi

echo -e "${GREEN}Starting Mita Router...${NC}"
echo -e "${YELLOW}HTTP API: http://localhost:8080${NC}"
echo -e "${YELLOW}Swagger UI: http://localhost:8080/swagger/ui${NC}"
echo -e "${YELLOW}OpenAPI JSON: http://localhost:8080/api-docs/oas-3.0.0.json${NC}"
echo ""

# Run with config
./build/mita_router -c config/router_config.json $DEV_MODE_FLAG -vv "$@"
