# BesuFuzz

BesuFuzz is where all the besu guided fuzzing tools live.

## eof-container

Performs differential fuzzing between Ethereum clients based on
the [txparse eofparse](https://github.com/holiman/txparse/blob/main/README.md#eof-parser-eofparse)
format. Note that only the initial `OK` and `err` values are used to determine if
there is a difference.

### Prototypical CLI Usage:

```shell
BesuFuzz eof-container \
  --tests-dir=~/git/ethereum/tests/EOFTests \
  --client=evm1=evmone-eofparse \
  --client=revm=revme bytecode
```

### Prototypical Gradle usage:

```shell
./gradlew fuzzEvmone fuzzReth
```

There are pre-written Gradle targets for `fuzzEthereumJS`, `fuzzEvmone`,
`fuzzGeth`, `fuzzNethermind`, and `fuzzReth`. Besu is always a fuzzing target.
The `fuzzAll` target will fuzz all clients.

## p256verify

Performs differential fuzzing of P256 signature verification between Java and Native (BoringSSL)
implementations of the P256Verify precompiled contract. Tests all combinations of signature
generation and verification to ensure consistency across implementations.

### Prototypical CLI Usage:

```shell
cd testfuzz/build/install/BesuFuzz
./bin/BesuFuzz p256verify \
  --corpus-dir=build/generated/p256-corpus \
  --timeout-seconds=3600
```

### Prototypical Gradle usage:

```shell
# Quick test with default settings
./gradlew fuzzP256Verify
```

The P256 fuzzer tests multiple mutation strategies including bit flips, boundary values,
curve attacks, and signature malleability. See `P256_FUZZER_README.md` for detailed documentation.

## state-test-fuzz

Performs coverage-guided fuzzing of the EVM using Ethereum state test JSON files. Supports
both single-threaded and parallel fuzzing modes with JaCoCo coverage tracking.

### Parallel Coverage-Guided Fuzzing (Recommended):

The `--parallel-guided` mode combines multi-threaded execution with shared coverage guidance,
achieving high throughput while intelligently prioritizing inputs that discover new code paths.

```shell
# Build the fuzzer with JaCoCo agent
./testfuzz/scripts/clean-build-fuzzer.sh

# Run parallel coverage-guided fuzzing
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz state-test-fuzz \
  --corpus-dir=path/to/corpus \
  --fork=Osaka \
  --duration=60s \
  --workers=4 \
  --parallel-guided \
  --guidance-regexp="org.hyperledger.besu.evm.*"
```

### Key Features:

- **AFL-style energy scheduling**: Prioritizes inputs that discover new coverage
- **Thread-safe coverage tracking**: All workers contribute to shared coverage bitmap
- **Automatic crash deduplication**: Saves unique crashes with metadata
- **Multiple mutation strategies**: Bytecode, transaction, storage, gas, and more

### CLI Options:

| Option | Description |
|--------|-------------|
| `--corpus-dir` | Directory containing seed corpus (JSON state tests) |
| `--fork` | EVM fork to target (e.g., Prague, Osaka) |
| `--duration` | How long to run (e.g., 30s, 5m, 1h) |
| `--workers` | Number of parallel workers (default: CPU cores) |
| `--parallel-guided` | Enable parallel coverage-guided mode |
| `--guidance-regexp` | Regex to filter which classes count for coverage |
| `--crash-dir` | Directory to save crash files (default: crashes/) |
| `--new-corpus-dir` | Directory to save new interesting inputs |

See `PARALLEL_FUZZER_ARCHITECTURE.md` for implementation details.

## validate-corpus

Validates a corpus of geth-produced enhanced state tests against Besu's execution to detect
cross-VM consensus divergences. This tool is essential for verifying that Besu produces identical
execution traces and state roots as other Ethereum clients.

### What It Does:

1. **Loads corpus files**: Reads JSON state test files with embedded `_info` metadata containing
   trace hashes and state roots from geth execution
2. **Parallel validation**: Executes each test against Besu using virtual threads (Java 21+)
3. **Hash comparison**: Compares MD5 trace hashes and state roots between geth and Besu
4. **Divergence detection**: Flags tests where Besu produces different results

### Basic Usage:

```shell
# Validate a corpus directory
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
  --corpus-dir=/path/to/enhanced/corpus \
  --fork=Osaka \
  --workers=16
```

### Triage Mode:

When dealing with many divergences, use `--triage` to cluster them by likely root cause:

```shell
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
  --corpus-dir=/path/to/corpus \
  --fork=Osaka \
  --triage
```

Triage mode groups divergences by their (expectedHash, actualHash) signature pair, dramatically
reducing the number of distinct issues to investigate. For example, 1,800 divergences might
cluster into just 50 distinct signatures representing 50 likely bugs.

### CLI Options:

| Option | Description |
|--------|-------------|
| `--corpus-dir` | Directory containing corpus files with cross-VM metadata (required) |
| `--fork` | EVM fork to use for execution (default: Prague) |
| `--workers`, `-w` | Number of worker threads (default: CPU cores) |
| `--triage` | Enable triage mode: cluster divergences by likely root cause |
| `--dump-traces` | Dump Besu traces for divergent tests (for debugging) |
| `--include-filtered` | Include filtered entries (STOP, depth=0) in trace dumps |
| `--output-dir`, `-o` | Output directory for reports and trace dumps |
| `--json` | Output machine-readable JSON report |
| `--quiet`, `-q` | Quiet mode (suppress progress, only show final result) |

### Exit Codes:

- **0**: All tests passed - consensus agreement
- **1**: Divergences detected - consensus disagreement found
- **2**: Errors occurred (IO, parsing, etc.)

### Example Output (Triage Mode):

```
========================================
Divergence Clustering Analysis
========================================

Total divergences/errors: 1801
Distinct clusters:        47
Compression ratio:        38.3x

By Divergence Type:
  STATE_ROOT_AND_TRACE_MISMATCH   15 clusters,  1200 tests
  TRACE_ONLY_MISMATCH             32 clusters,   601 tests

Top 10 Clusters (by impact):
----------------------------
#1: Cluster[54b7c078→abf995f6] size=500 type=STATE_ROOT_AND_TRACE_MISMATCH
    Representatives:
      - 54b7c078fbf487f9_728.json
      - 54b7c078fbf487f9_518.json
      ...
```

### Workflow:

1. **Generate enhanced corpus with geth**:
   ```shell
   # Run geth's statetest fuzzer to produce corpus with trace metadata
   go-fuzz -bin=./statetest-fuzz.zip -workdir=/tmp/corpus
   ```

2. **Validate against Besu**:
   ```shell
   ./BesuFuzz validate-corpus --corpus-dir=/tmp/corpus/corpus --fork=Osaka --triage
   ```

3. **Investigate divergences**:
   - Use triage output to identify distinct clusters
   - Use `--dump-traces` to get detailed Besu traces for debugging
   - Compare traces side-by-side with geth output

See `CROSS_VM_CONSENSUS_COMPARISON_PLAN.md` for architecture details.