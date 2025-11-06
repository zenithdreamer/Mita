#!/bin/bash

# Script to fix ownership of the Mita project folder
# This changes all files back to the current user

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURRENT_USER="$(whoami)"

echo "Fixing permissions for: $SCRIPT_DIR"
echo "Changing ownership to: $CURRENT_USER"
echo ""

# Change ownership recursively
sudo chown -R "$CURRENT_USER:$CURRENT_USER" "$SCRIPT_DIR"

if [ $? -eq 0 ]; then
    echo "Ownership successfully changed to $CURRENT_USER"
    echo ""
    echo "You can now build without sudo:"
    echo "  cd router/build"
    echo "  cmake .."
    echo "  make"
else
    echo "Failed to change ownership"
    exit 1
fi
