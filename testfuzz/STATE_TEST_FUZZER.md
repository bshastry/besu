# State Test Fuzzer

A high-performance multi-threaded fuzzer for Besu's EVM implementation using Ethereum state test mutations.

## Overview

The state test fuzzer processes state tests directly in-memory, bypassing IPC overhead for maximum throughput. It applies mutations to corpus state tests using strategies ported from [goevmlab](https://github.com/holiman/goevmlab).

## Features

- **Direct Transaction Processing**: Executes state tests using Besu's `TransactionProcessor` directly
- **Multi-threaded Execution**: Scales with available CPU cores
- **Goevmlab Mutation Strategies**:
  - Bytecode mutations (random byte, increment/decrement, bit flip)
  - Gas mutations (interesting values, boundary conditions)
  - Value mutations (wei amounts, overflow detection)
  - Calldata mutations
  - Opcode-smart mutations (EVM-aware changes)
  - Havoc mode (AFL-style stacked random mutations)
- **JaCoCo Coverage Guidance**: Optional coverage-guided fuzzing with `--guidance-regexp`
- **Crash Collection**: Automatically saves crash-inducing inputs with metadata

## Building

```bash
./gradlew :testfuzz:installDist -x test
```

## Usage

### Basic Usage

```bash
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz state-test-fuzz \
  --corpus-dir=/path/to/corpus \
  --duration=1h \
  --fork=Prague
```

### Full Options

```bash
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz state-test-fuzz \
  --corpus-dir=/path/to/corpus \    # Directory with state test JSON files (required)
  --fork=Prague \                   # Target fork (default: Prague)
  --duration=1h \                   # Duration: 1h, 30m, 10s, or "infinite"
  --workers=8 \                     # Worker threads (default: CPU cores)
  --crash-dir=./crashes \           # Where to save crashes
  --new-corpus-dir=./new-corpus \   # Save coverage-increasing inputs here
  --guidance-regexp="org.hyperledger.besu.evm.*"  # JaCoCo coverage guidance
```

### Example with Coverage Guidance

```bash
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz state-test-fuzz \
  --corpus-dir=/path/to/goevmlab/corpus \
  --fork=Prague \
  --duration=infinite \
  --workers=4 \
  --guidance-regexp="org.hyperledger.besu.evm.*" \
  --new-corpus-dir=./new-corpus
```

## Corpus

The fuzzer expects a directory containing Ethereum state test JSON files. You can generate a corpus using [goevmlab](https://github.com/holiman/goevmlab):

```bash
# Generate corpus from Ethereum tests
goevmlab statetest-gen --output-dir ./corpus
```

Or use an existing corpus like the one from goevmlab.

## Performance

Typical throughput with 4 workers on modern hardware:
- ~1000 executions/second (simple fuzzing mode)
- ~500 executions/second (coverage-guided mode with JaCoCo)

## Mutation Strategies

| Strategy | Weight | Description |
|----------|--------|-------------|
| bytecode | 10 | Mutates contract bytecode (respecting PUSH operands) |
| gas | 8 | Tests gas boundary conditions |
| value | 8 | Mutates transaction value (wei amounts) |
| calldata | 8 | Mutates transaction input data |
| opcode-smart | 10 | EVM-aware opcode mutations |
| havoc | 12 | AFL-style stacked random mutations |

Strategies are selected randomly based on their weights.

## Output

### Progress Output

```
=== Besu State Test Fuzzer ===

Corpus: 54861 files
Fork: Prague
Crash dir: /path/to/crashes

Starting multi-threaded fuzzing with 4 workers...

elapsed: 00:01:30 | execs: 90000 (1000.0/sec) | crashes: 0 | workers: 4
```

### Crash Files

When a crash is found, two files are saved:
- `crash-<timestamp>-<hash>.json` - The mutated state test that caused the crash
- `crash-<timestamp>-<hash>.txt` - Metadata including error message

## Architecture

```
StateTestFuzzSubCommand (CLI interface)
    |
    +-- StateTestFuzzTarget (fuzz target implementation)
    |       |
    |       +-- StateTestExecutor (direct tx processing)
    |       +-- CombinedMutationStrategy (mutation orchestration)
    |               |
    |               +-- BytecodeMutationStrategy
    |               +-- GasMutationStrategy
    |               +-- ValueMutationStrategy
    |               +-- CalldataMutationStrategy
    |               +-- OpcodeSmartMutationStrategy
    |               +-- HavocMutationStrategy
    |
    +-- Fuzzer (JaCoCo-guided loop, when --guidance-regexp is set)
```

## Comparison with Go Fuzzer

This Java implementation offers advantages over the external Go-based fuzzer:
- No IPC overhead (direct method calls vs. subprocess execution)
- JaCoCo integration for coverage-guided fuzzing
- Easier integration with Besu's test infrastructure
- Can target internal APIs not exposed via CLI
