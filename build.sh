#!/bin/bash
set -e

# Build configuration
BINARY_NAME="nat-info"
VERSION="${VERSION:-$(date +%Y%m%d-%H%M%S)}"
BUILD_DIR="dist"
LDFLAGS="-s -w -X main.version=${VERSION}"

# Clean previous builds
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}

echo "Building ${BINARY_NAME} for multiple platforms..."
echo "================================================"

# Function to build for a specific platform
build_platform() {
    local os=$1
    local arch=$2
    local output_path="${BUILD_DIR}/${BINARY_NAME}-${os}-${arch}"
    
    echo "Building for ${os}/${arch}..."
    
    if [ "$os" = "linux" ]; then
        # Use Docker for Linux builds to ensure compatibility
        # Installing UPX and compressing inside the container to reduce size
        docker run --rm \
            -v "$(pwd)":/usr/src/nat-info \
            -w /usr/src/nat-info \
            -e GOOS=${os} \
            -e GOARCH=${arch} \
            -e CGO_ENABLED=0 \
            golang:1.22-alpine \
            sh -c "apk add --no-cache upx && \
                   go build -ldflags '${LDFLAGS}' -trimpath -o ${output_path} . && \
                   echo 'Compressing with UPX...' && \
                   upx --best --lzma ${output_path}"
    else
        # Native build for macOS
        GOOS=${os} GOARCH=${arch} CGO_ENABLED=0 go build \
            -ldflags "${LDFLAGS}" \
            -trimpath \
            -o "${output_path}" .
            
        # Try to compress with UPX if available (host side for macOS)
        if [ -f "${output_path}" ] && command -v upx >/dev/null 2>&1; then
             echo "  Compressing ${output_path} with UPX..."
             upx --best --lzma "${output_path}" >/dev/null 2>&1 || echo "  ⚠ UPX compression failed/skipped"
        fi
    fi
    
    # Show binary size
    if [ -f "${output_path}" ]; then
        size=$(du -h "${output_path}" | cut -f1)
        echo "  ✓ Built: ${output_path} (${size})"
    else
        echo "  ✗ Failed to build ${os}/${arch}"
        return 1
    fi
}

# Build for all platforms
build_platform "linux" "amd64"
build_platform "linux" "arm64"
build_platform "darwin" "amd64"
build_platform "darwin" "arm64"

echo ""
echo "================================================"
echo "Build complete! Binaries are in ${BUILD_DIR}/"
echo ""
ls -lh ${BUILD_DIR}/

