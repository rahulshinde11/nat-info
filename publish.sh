#!/bin/bash
set -e

IMAGE_NAME="shinde11/nat-info"

echo "Step 1: Building binaries..."
./build.sh

echo "Step 2: Building Docker image..."
docker build -t ${IMAGE_NAME}:latest .

echo "Step 3: Pushing Docker image..."
docker push ${IMAGE_NAME}:latest

echo ""
echo "Success! Image pushed to ${IMAGE_NAME}:latest"
echo "Server: docker run -d -p 80:80 -e DOMAIN=http://your-domain.com ${IMAGE_NAME}:latest"
echo "Client: curl -sL http://your-domain.com | sh"
