# State Test Fuzzer

A high-performance multi-threaded fuzzer for Besu's EVM implementation using Ethereum state test mutations.

## Overview

The state test fuzzer processes state tests directly in-memory, bypassing IPC overhead for maximum throughput. It applies mutations to corpus state tests using strategies ported from [goevmlab](https://github.com/holiman/goevmlab).

## Features

- **Direct Transaction Processing**: Executes state tests using Besu's `TransactionProcessor` directly
- **Multi-threaded Execution**: Scales with available CPU cores
- **Goevmlab Mutation Strategies** (15 strategies ported from Go):
  - **Core**: bytecode, opcode-smart, gas, value, calldata, storage
  - **AFL-inspired**: arithmetic (±1-35), boundary values, dictionary injection, bit-flipping
  - **Structural**: block operations (delete/clone/insert/overwrite), transaction fields, account fields
  - **Advanced**: havoc (2-128 stacked mutations), splicing (corpus-based bytecode combining)
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

All 15 strategies from goevmlab have been ported to Java:

### Core Strategies

| Strategy | Weight | Description |
|----------|--------|-------------|
| bytecode | 10 | Mutates contract bytecode (respecting PUSH operands) |
| opcode-smart | 10 | EVM-aware opcode mutations (stack, memory, control flow) |
| gas | 8 | Tests gas boundary conditions (21000, block gas limit, etc.) |
| value | 6 | Mutates transaction value (wei amounts, excludes max uint256) |
| calldata | 8 | Mutates transaction input data |
| storage | 6 | Mutates pre-state storage keys/values |

### AFL-Inspired Strategies

| Strategy | Weight | Description |
|----------|--------|-------------|
| arithmetic | 6 | AFL-style ±1-35 mutations on numeric fields |
| boundary | 6 | Replaces values with interesting boundaries (gas costs, etc.) |
| dictionary | 6 | Injects EVM tokens (opcodes, precompiles, selectors) |
| bitflip | 6 | AFL bit-flipping stages (FLIP1/2/4/8) |

### Structural Strategies

| Strategy | Weight | Description |
|----------|--------|-------------|
| blockops | 6 | Block operations: delete, clone, insert, overwrite |
| txfields | 6 | Mutates tx nonce, gasPrice, to address, EIP-1559 fields |
| accountfields | 6 | Mutates account balance and nonce in pre-state |

### Advanced Strategies

| Strategy | Weight | Description |
|----------|--------|-------------|
| havoc | 5 | AFL havoc stage: stacks 2-128 random mutations |
| splicing | 4 | Combines bytecode from different corpus inputs (requires >= 2 corpus entries) |

Strategies are selected randomly based on their weights. The combined strategy automatically
enables splicing when the corpus has at least 2 entries.

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
    |       |       |
    |       |       +-- Core: Bytecode, OpcodesSmart, Gas, Value, Calldata, Storage
    |       |       +-- AFL: Arithmetic, Boundary, Dictionary, BitFlip
    |       |       +-- Structural: BlockOps, TxFields, AccountFields
    |       |       +-- Advanced: Havoc (delegates to all above), Splicing
    |       |
    |       +-- StateTestCorpusProvider (thread-safe corpus access for splicing)
    |
    +-- Fuzzer (JaCoCo-guided loop, when --guidance-regexp is set)
```

## Thread Safety

The fuzzer is designed for safe multi-threaded execution:

- **Corpus**: Loaded once at startup, then read-only access via `StateTestCorpusProvider`
- **Workers**: Each worker thread gets its own `StateTestExecutor` and `CombinedMutationStrategy`
- **Mutations**: All mutations create new byte arrays (never modify corpus entries in-place)
- **Random**: Uses `ThreadLocalRandom` for thread-safe random number generation

## Comparison with Go Fuzzer

This Java implementation offers advantages over the external Go-based fuzzer:
- No IPC overhead (direct method calls vs. subprocess execution)
- JaCoCo integration for coverage-guided fuzzing
- Easier integration with Besu's test infrastructure
- Can target internal APIs not exposed via CLI
