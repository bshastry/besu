#!/usr/bin/env bash
##
## Copyright contributors to Besu.
##
## Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
## the License. You may obtain a copy of the License at
##
## http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
## an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
## specific language governing permissions and limitations under the License.
##
## SPDX-License-Identifier: Apache-2.0
##

# Replay a crash file found by the state test fuzzer
# Uses the StateTestExecutor directly to reproduce the crash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BESU_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

usage() {
    echo "Usage: $0 <crash-file.json> [--fork FORK] [--timeout SECONDS] [--verbose]"
    echo ""
    echo "Arguments:"
    echo "  crash-file.json  Path to the crash JSON file to replay"
    echo "  --fork FORK      Fork to use (default: Osaka)"
    echo "  --timeout SECS   Timeout in seconds (default: 60)"
    echo "  --verbose        Show verbose output"
    echo ""
    echo "Example:"
    echo "  $0 crashes/crash-1234567890-abcd1234.json --fork Prague"
    exit 1
}

# Default values
FORK="Osaka"
TIMEOUT=60
VERBOSE=false
CRASH_FILE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --fork)
            FORK="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            if [[ -z "$CRASH_FILE" ]]; then
                CRASH_FILE="$1"
            else
                echo "Unknown argument: $1"
                usage
            fi
            shift
            ;;
    esac
done

if [[ -z "$CRASH_FILE" ]]; then
    echo "Error: No crash file specified"
    usage
fi

if [[ ! -f "$CRASH_FILE" ]]; then
    echo "Error: Crash file not found: $CRASH_FILE"
    exit 1
fi

# Check if fuzzer is built
FUZZER_LIB="$BESU_ROOT/testfuzz/build/install/BesuFuzz/lib"
if [[ ! -d "$FUZZER_LIB" ]]; then
    echo "Error: Fuzzer not built. Run clean-build-fuzzer.sh first."
    exit 1
fi

echo "=== Crash Replay ==="
echo "Crash file: $CRASH_FILE"
echo "Fork: $FORK"
echo "Timeout: ${TIMEOUT}s"
echo ""

# Create Java replay class
REPLAY_CLASS=$(mktemp --suffix=.java)
REPLAY_NAME=$(basename "$REPLAY_CLASS" .java)

cat > "$REPLAY_CLASS" << 'JAVA_EOF'
import java.nio.file.Files;
import java.nio.file.Paths;
import org.hyperledger.besu.testfuzz.StateTestExecutor;
import org.hyperledger.besu.testfuzz.StateTestExecutor.ExecutionResult;

public class CrashReplay {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: CrashReplay <crash.json> <fork>");
            System.exit(1);
        }

        String crashFile = args[0];
        String fork = args[1];

        System.out.println("Loading crash file: " + crashFile);
        byte[] data = Files.readAllBytes(Paths.get(crashFile));
        System.out.println("File size: " + data.length + " bytes");
        System.out.println("Fork: " + fork);
        System.out.println("");

        StateTestExecutor executor = new StateTestExecutor(fork);

        System.out.println("Executing state test...");
        long start = System.currentTimeMillis();

        try {
            ExecutionResult result = executor.execute(data);
            long elapsed = System.currentTimeMillis() - start;

            System.out.println("");
            System.out.println("=== Result ===");
            System.out.println("Crashed: " + result.isCrashed());
            System.out.println("Success: " + result.isSuccess());
            System.out.println("Error: " + (result.getError() != null ? result.getError() : "none"));
            System.out.println("State Root: " + (result.getStateRoot() != null ? result.getStateRoot() : "N/A"));
            System.out.println("Gas Used: " + result.getGasUsed());
            System.out.println("Elapsed: " + elapsed + "ms");
            System.out.println("");
            System.out.println("Stats: " + executor.getStats());

            // Exit with appropriate code
            if (result.isCrashed()) {
                System.out.println("");
                System.out.println("CRASH REPRODUCED!");
                System.exit(1);
            } else if (!result.isSuccess()) {
                System.out.println("");
                System.out.println("Execution failed but not classified as crash");
                System.exit(2);
            } else {
                System.out.println("");
                System.out.println("Crash NOT reproduced - test passed");
                System.exit(0);
            }

        } catch (Exception e) {
            long elapsed = System.currentTimeMillis() - start;
            System.out.println("");
            System.out.println("=== Exception ===");
            System.out.println("Type: " + e.getClass().getName());
            System.out.println("Message: " + e.getMessage());
            System.out.println("Elapsed: " + elapsed + "ms");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
JAVA_EOF

# Rename to CrashReplay.java
mv "$REPLAY_CLASS" "/tmp/CrashReplay.java"

echo "Compiling replay harness..."
cd "$FUZZER_LIB"

# Compile the replay class
if ! javac -cp "*" /tmp/CrashReplay.java -d /tmp/ 2>&1; then
    echo "Error: Failed to compile replay harness"
    rm -f /tmp/CrashReplay.java /tmp/CrashReplay.class
    exit 1
fi

echo "Running replay..."
echo ""

# Run with timeout
if timeout "$TIMEOUT" java -cp "*:/tmp" CrashReplay "$CRASH_FILE" "$FORK"; then
    EXIT_CODE=$?
else
    EXIT_CODE=$?
    if [[ $EXIT_CODE -eq 124 ]]; then
        echo ""
        echo "=== TIMEOUT ==="
        echo "Execution timed out after ${TIMEOUT}s"
        echo "This may indicate an infinite loop or very slow computation"
    fi
fi

# Cleanup
rm -f /tmp/CrashReplay.java /tmp/CrashReplay.class

exit $EXIT_CODE
