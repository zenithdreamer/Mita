#!/bin/bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}=== Mita Router Full Stack Startup ===${NC}"
echo ""

# Check and install system dependencies
echo -e "${YELLOW}Checking system dependencies...${NC}"
REQUIRED_PACKAGES="build-essential cmake pkg-config libdbus-1-dev libnm-dev nlohmann-json3-dev libssl-dev"
MISSING_PACKAGES=""

for pkg in $REQUIRED_PACKAGES; do
    if ! dpkg -l | grep -q "^ii  $pkg"; then
        MISSING_PACKAGES="$MISSING_PACKAGES $pkg"
    fi
done

if [ -n "$MISSING_PACKAGES" ]; then
    echo -e "${YELLOW}Missing packages:$MISSING_PACKAGES${NC}"
    echo -e "${YELLOW}Installing missing packages...${NC}"
    sudo apt-get update
    sudo apt-get install -y $MISSING_PACKAGES
    echo -e "${GREEN}Dependencies installed successfully${NC}"
else
    echo -e "${GREEN}All dependencies are installed${NC}"
fi
echo ""

# Build backend
echo -e "${YELLOW}Building C++ backend...${NC}"
cd router
./build.sh
cd ..

# Load nvm early
if [ -n "$SUDO_USER" ]; then
    export NVM_DIR="/home/$SUDO_USER/.nvm"
else
    export NVM_DIR="$HOME/.nvm"
fi
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"


echo ""
echo -e "${BLUE}Starting services...${NC}"
echo ""
echo -e "${YELLOW}Backend will start on: http://localhost:8080${NC}"
echo -e "${YELLOW}  - API endpoints: http://localhost:8080/api/*${NC}"
echo -e "${YELLOW}  - Swagger UI: http://localhost:8080/swagger/ui${NC}"
echo -e "${YELLOW}  - OpenAPI JSON: http://localhost:8080/api-docs/oas-3.0.0.json${NC}"
echo ""
echo -e "${YELLOW}Frontend will start on: http://localhost:5173${NC}"
echo ""
echo -e "${GREEN}Press Ctrl+C to stop all services${NC}"
echo ""

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
    echo ""
    echo -e "${YELLOW}Stopping all services...${NC}"

    # Determine if we need sudo for killing processes
    USE_SUDO=""
    if [ "$EUID" -eq 0 ]; then
        USE_SUDO=""  # Already root
    else
        USE_SUDO="sudo"
    fi

    # Kill frontend
    if [ -n "$FRONTEND_PID" ]; then
        $USE_SUDO kill $FRONTEND_PID 2>/dev/null
        $USE_SUDO pkill -P $FRONTEND_PID 2>/dev/null  # Kill child processes
    fi

    # Kill backend
    if [ -n "$BACKEND_PID" ]; then
        $USE_SUDO kill $BACKEND_PID 2>/dev/null
        $USE_SUDO pkill -P $BACKEND_PID 2>/dev/null  # Kill child processes
    fi

    # # Cleanup any remaining vite/pnpm processes (force kill with sudo if needed)
    # $USE_SUDO pkill -9 -f "vite" 2>/dev/null
    # $USE_SUDO pkill -9 -f "pnpm dev" 2>/dev/null
    # $USE_SUDO pkill -9 -f "esbuild" 2>/dev/null

    # # Kill any mita_router processes
    # $USE_SUDO pkill -f "mita_router" 2>/dev/null

    echo -e "${GREEN}All services stopped${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# Start backend in background
cd router
./run.sh "$@" &
BACKEND_PID=$!
cd ..

if ! kill -0 $BACKEND_PID 2>/dev/null; then
    echo -e "${RED}Backend failed to start${NC}"
    exit 1
fi

# Start frontend
echo -e "${GREEN}Starting frontend...${NC}"
cd frontend

# Install frontend dependencies if needed
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}Installing frontend dependencies...${NC}"
    pnpm install
    echo -e "${GREEN}Frontend dependencies installed${NC}"
fi

# Wait for backend OpenAPI endpoint to be ready
echo -e "${YELLOW}Waiting for backend OpenAPI endpoint...${NC}"
MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -s -f http://localhost:8080/api-docs/oas-3.0.0.json > /dev/null 2>&1; then
        echo -e "${GREEN}Backend is ready!${NC}"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo -e "${YELLOW}Attempt $RETRY_COUNT/$MAX_RETRIES - waiting...${NC}"
    sleep 1
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo -e "${RED}Backend OpenAPI endpoint did not become available${NC}"
    exit 1
fi

sleep 2

echo -e "${YELLOW}Generating TypeScript types from OpenAPI spec...${NC}"
pnpm generate:api

pnpm dev &
FRONTEND_PID=$!
cd ..

# Wait for all background jobs
wait
