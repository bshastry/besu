# Cross-VM Trace Comparison Script

This script automates the comparison of EVM execution traces between geth and Besu for divergent test clusters identified by the `validate-corpus` command.

## Overview

When `validate-corpus` detects consensus divergences between Besu and geth, it produces a `validation_report.json` file containing:
- Individual divergent tests
- Cluster information (tests grouped by their divergence signature)

This script takes that report and:
1. Extracts unique divergence clusters
2. Selects one representative test from each cluster
3. Generates traces using both geth and Besu
4. Compares the traces side-by-side
5. Categorizes the divergence root cause
6. Produces structured reports for investigation

## Prerequisites

- **BesuFuzz**: Built via `./gradlew :testfuzz:installDist`
- **geth statetest-trace**: Built from go-ethereum source
- **jq**: For JSON processing
- **diff**: Standard Unix diff tool

## Quick Start

```bash
# From the besu root directory
cd testfuzz/scripts

# Run comparison on a validation report
./compare-traces.sh ../validation-results-2025-12-09/validation_report.json

# Specify output directory
./compare-traces.sh -o ./my-comparison validation_report.json

# Process only first 10 clusters (for quick testing)
./compare-traces.sh -n 10 -v validation_report.json
```

## Usage

```
Usage: compare-traces.sh [OPTIONS] <validation-report.json>

Options:
    -o, --output-dir DIR     Output directory (default: trace-comparison-YYYY-MM-DD)
    -f, --fork FORK          EVM fork to use (default: Osaka)
    -g, --geth-root DIR      Path to go-ethereum root (default: ../go-ethereum)
    -n, --max-clusters N     Maximum number of clusters to process (default: all)
    -v, --verbose            Enable verbose output
    -h, --help               Show this help message
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GETH_ROOT` | Path to go-ethereum source | `../go-ethereum` (relative to besu) |
| `FORK` | EVM fork for execution | `Osaka` |
| `MAX_CLUSTERS` | Max clusters to process | `0` (all) |
| `VERBOSE` | Enable debug output | `false` |

## Output Structure

```
trace-comparison-2025-12-09/
├── summary.json           # Machine-readable summary
├── summary.txt            # Human-readable summary
└── cluster-<hash>/        # One directory per cluster
    ├── test.json          # Original test file
    ├── besu-trace.jsonl   # Besu execution trace
    ├── geth-trace.jsonl   # Geth execution trace
    ├── diff.txt           # Side-by-side diff
    └── report.json        # Structured comparison report
```

### Per-Cluster Report Fields

| Field | Description |
|-------|-------------|
| `clusterKey` | Unique cluster identifier (expectedHash_actualHash) |
| `testFile` | Path to the representative test |
| `testName` | Name of the test within the file |
| `fork` | Fork used for execution |
| `expectedTraceHash` | Trace hash from geth (expected) |
| `actualTraceHash` | Trace hash from Besu (actual) |
| `besuTraceHash` | Freshly computed Besu trace hash |
| `gethTraceHash` | Freshly computed geth trace hash |
| `besuStateRoot` | Final state root from Besu |
| `gethStateRoot` | Final state root from geth |
| `besuTraceLines` | Number of trace lines from Besu |
| `gethTraceLines` | Number of trace lines from geth |
| `firstDivergence` | Description of first differing instruction |
| `category` | Divergence category (see below) |
| `clusterSize` | Number of tests in this cluster |
| `hashMatch` | Whether trace hashes match |
| `stateRootMatch` | Whether state roots match |

### Divergence Categories

| Category | Description | Typical Cause |
|----------|-------------|---------------|
| `missing_opcode` | Besu reports "opcode not defined" | Missing EIP implementation |
| `opcode_mismatch` | Different opcode names | Opcode mapping difference |
| `state_root_mismatch` | Same trace but different state | State transition bug |
| `trace_length_mismatch` | Different execution lengths | Early termination or extra steps |
| `unknown` | Cannot automatically categorize | Requires manual investigation |

## Examples

### Basic Workflow

```bash
# 1. Run validation to find divergences
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
  --corpus-dir=/tmp/corpus \
  --fork=Osaka \
  --triage \
  --output-dir=./validation-results/

# 2. Compare traces for divergent clusters
./testfuzz/scripts/compare-traces.sh \
  ./validation-results/validation_report.json

# 3. Review the summary
cat trace-comparison-*/summary.txt

# 4. Investigate specific clusters
cat trace-comparison-*/cluster-*/report.json | jq '.category'
```

### Quick Investigation

```bash
# Process only first 5 clusters with verbose output
./compare-traces.sh -n 5 -v validation_report.json

# View first diverging instruction for each cluster
jq -r '.clusters[] | "\(.clusterKey): \(.firstDivergence)"' \
  trace-comparison-*/summary.json
```

### CI/CD Integration

```bash
#!/bin/bash
# ci-trace-check.sh

./testfuzz/scripts/compare-traces.sh \
  --output-dir="./ci-traces-${BUILD_NUMBER}" \
  --max-clusters=50 \
  validation_report.json

# Check for critical divergences
MISSING_OPCODES=$(jq '[.clusters[] | select(.category=="missing_opcode")] | length' \
  "./ci-traces-${BUILD_NUMBER}/summary.json")

if [[ "$MISSING_OPCODES" -gt 0 ]]; then
  echo "CRITICAL: $MISSING_OPCODES missing opcode divergences found"
  exit 1
fi
```

### Compare Specific Fork

```bash
# Test against Prague fork
FORK=Prague ./compare-traces.sh validation_report.json

# Or use the flag
./compare-traces.sh -f Cancun validation_report.json
```

## Interpreting Results

### Missing Opcode (EIP Not Implemented)

```
Cluster: 4e9c191c8e1e6dde
  Category: missing_opcode
  First divergence: pc=14: besu=opcode 0x1e not defined, geth=CLZ
```

This indicates Besu doesn't implement the CLZ opcode (EIP-7939). The fix would be to implement the EIP in Besu's EVM.

### State Root Mismatch

```
Cluster: abc123def456
  Category: state_root_mismatch
  besuStateRoot: 0x1234...
  gethStateRoot: 0x5678...
```

Both VMs executed the same trace but ended with different state. This is a critical consensus bug that needs investigation of the state transition logic.

### Trace Length Mismatch

```
Cluster: xyz789
  Category: trace_length_mismatch
  besuTraceLines: 42
  gethTraceLines: 50
```

One VM executed more instructions than the other. Check for early termination conditions or gas calculation differences.

## Troubleshooting

### "BesuFuzz not found"

```bash
# Build BesuFuzz first
./gradlew :testfuzz:installDist
```

### "statetest-trace not found"

```bash
# Set GETH_ROOT or build manually
export GETH_ROOT=/path/to/go-ethereum
cd $GETH_ROOT
go build -o statetest-trace ./tests/fuzzers/statetest/cmd/statetest-trace/
```

### "Test file not found"

The validation report references test files that may have been moved or deleted. Ensure the corpus directory still exists at the paths recorded in the report.

### Slow Processing

```bash
# Process fewer clusters for quick analysis
./compare-traces.sh -n 20 validation_report.json

# Use verbose mode to see progress
./compare-traces.sh -v validation_report.json
```

## Related Commands

- `BesuFuzz validate-corpus` - Generate the validation report
- `BesuFuzz dump-trace` - Dump trace for a single test
- `geth statetest-trace dump` - Dump geth trace for a test

## See Also

- [CROSS_VM_VALIDATION_GUIDE.md](../CROSS_VM_VALIDATION_GUIDE.md) - Complete validation lifecycle
- [README.md](../README.md) - BesuFuzz overview
- [CROSS_VM_CONSENSUS_COMPARISON_PLAN.md](../CROSS_VM_CONSENSUS_COMPARISON_PLAN.md) - Architecture details
