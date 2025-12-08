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