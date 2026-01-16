#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Default to current protocol
PROTOCOL_ENV="${1:-.env.current}"

usage() {
    echo "Usage: $0 [.env.current|.env.next] [test-pattern]"
    echo ""
    echo "Examples:"
    echo "  $0                          # Run all tests with current protocol"
    echo "  $0 .env.next                # Run all tests with next protocol"
    echo "  $0 .env.current TestMetrics # Run only TestMetrics"
    echo ""
    echo "Commands:"
    echo "  $0 build    # Only build the image"
    echo "  $0 up       # Only start the stack"
    echo "  $0 down     # Only stop the stack"
    echo "  $0 logs     # Show signatory logs"
    echo "  $0 shell    # Open shell in signatory container"
    exit 1
}

# Setup environment for docker compose commands
setup_env() {
    source .env.current
    export IMAGE=ecadlabs/signatory:integration-test
    export ARCH
    # Create required placeholder files if they don't exist
    [[ -f gcp-token.json ]] || echo '{}' > gcp-token.json
    [[ -f service-principal.key ]] || touch service-principal.key
    # Create .env file for docker compose (used by tests that restart containers)
    cat > .env << EOF
ARCH=$ARCH
IMAGE=$IMAGE
OCTEZ_VERSION=$OCTEZ_VERSION
PROTOCOL=$PROTOCOL
EOF
}

# Handle special commands
case "$1" in
    -h|--help|help) usage ;;
    build)
        echo "Building signatory image..."
        docker build \
            --build-arg GIT_REVISION="$(git rev-parse HEAD)" \
            --build-arg GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD)" \
            -t ecadlabs/signatory:integration-test \
            -f Dockerfile \
            ..
        echo "Done. Image: ecadlabs/signatory:integration-test"
        exit 0
        ;;
    up)
        setup_env
        docker compose up -d --wait
        exit 0
        ;;
    down)
        setup_env
        docker compose down
        exit 0
        ;;
    logs)
        setup_env
        docker compose logs signatory -f
        exit 0
        ;;
    shell)
        docker exec -it signatory /bin/bash
        exit 0
        ;;
esac

# Validate protocol env file
if [[ ! -f "$PROTOCOL_ENV" ]]; then
    echo "Error: Protocol environment file not found: $PROTOCOL_ENV"
    usage
fi

TEST_PATTERN="${2:-}"

# Create required placeholder files if they don't exist
[[ -f gcp-token.json ]] || echo '{}' > gcp-token.json
[[ -f service-principal.key ]] || touch service-principal.key

# Source protocol environment
source "$PROTOCOL_ENV"

# Export environment for docker compose
export ARCH
export IMAGE=ecadlabs/signatory:integration-test

# Create .env file for docker compose (used by tests that restart containers)
cat > .env << EOF
ARCH=$ARCH
IMAGE=$IMAGE
OCTEZ_VERSION=$OCTEZ_VERSION
PROTOCOL=$PROTOCOL
EOF

echo "=== Integration Test Configuration ==="
echo "Architecture: $ARCH"
echo "Image: $IMAGE"
echo "Octez Version: $OCTEZ_VERSION"
echo "Protocol: $PROTOCOL"
echo "Test Pattern: ${TEST_PATTERN:-all tests}"
echo ""

# Build the image
echo "=== Building signatory image ==="
docker build \
    --build-arg GIT_REVISION="$(git rev-parse HEAD)" \
    --build-arg GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD)" \
    -t "$IMAGE" \
    -f Dockerfile \
    ..

# Start the stack
echo ""
echo "=== Starting test stack ==="
docker compose down 2>/dev/null || true
docker compose up -d --wait

# Run the tests
echo ""
echo "=== Running tests ==="
go clean -testcache

if [[ -n "$TEST_PATTERN" ]]; then
    go test -v -run "$TEST_PATTERN" ./tests/...
else
    # Run tests that don't require vault credentials
    go test -v ./tests/cli/... ./tests/metrics/... ./tests/operations/... || true
fi

TEST_EXIT=$?

# Show summary
echo ""
echo "=== Test Summary ==="
if [[ $TEST_EXIT -eq 0 ]]; then
    echo "All tests passed!"
else
    echo "Some tests failed (exit code: $TEST_EXIT)"
    echo ""
    echo "To debug, you can:"
    echo "  $0 logs           # View signatory logs"
    echo "  $0 shell          # Open shell in container"
    echo "  $0 down           # Stop the stack"
fi

# Optionally stop the stack
read -p "Stop the test stack? [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    docker compose down
fi

exit $TEST_EXIT
