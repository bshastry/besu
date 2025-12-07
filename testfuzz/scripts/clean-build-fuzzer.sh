#!/usr/bin/env bash
# Clean build of state test fuzzer and all its dependencies
# This ensures all code is recompiled from the current branch

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BESU_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Clean Build: Besu State Test Fuzzer ==="
echo "Besu root: $BESU_ROOT"
echo ""

cd "$BESU_ROOT"

echo "Step 1: Stopping Gradle daemon to ensure fresh build..."
./gradlew --stop 2>/dev/null || true

echo ""
echo "Step 2: Cleaning all build artifacts..."
./gradlew clean

echo ""
echo "Step 3: Building fuzzer and all dependencies from scratch..."
./gradlew \
    :datatypes:jar \
    :crypto:algorithms:jar \
    :ethereum:core:jar \
    :ethereum:referencetests:jar \
    :evm:jar \
    :testfuzz:installDist \
    --no-build-cache

echo ""
echo "Step 4: Copying JaCoCo agent..."
./gradlew :testfuzz:copyJacoco

echo ""
echo "Step 5: Verifying installation..."
FUZZER_BIN="$BESU_ROOT/testfuzz/build/install/BesuFuzz/bin/BesuFuzz"
JACOCO_JAR="$BESU_ROOT/testfuzz/build/install/BesuFuzz/lib/jacocoagent.jar"
if [[ -f "$FUZZER_BIN" ]]; then
    echo "Fuzzer binary: $FUZZER_BIN"
else
    echo "ERROR: Fuzzer binary not found at $FUZZER_BIN"
    exit 1
fi

if [[ -f "$JACOCO_JAR" ]]; then
    echo "JaCoCo agent: $JACOCO_JAR"
    echo "Build successful!"
else
    echo "ERROR: JaCoCo agent not found at $JACOCO_JAR"
    exit 1
fi

echo ""
echo "=== Build Complete ==="
echo ""
echo "To run the fuzzer:"
echo "  $FUZZER_BIN state-test-fuzz --corpus-dir=<dir> --fork=<fork>"
