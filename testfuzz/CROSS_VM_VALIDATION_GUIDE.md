# Cross-VM Corpus Validation Guide

This guide covers the complete workflow for validating Besu's EVM execution against geth-produced test corpora and triaging any consensus divergences.

## Prerequisites

```shell
# Build the BesuFuzz tool
./gradlew :testfuzz:installDist

# Verify installation
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz --help
```

## Quick Start

```shell
# Validate a corpus with triage (recommended)
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
  --corpus-dir=/path/to/corpus \
  --fork=Osaka \
  --triage
```

## Complete Validation Lifecycle

### Phase 1: Generate Enhanced Corpus (geth side)

The corpus must contain state test JSON files with embedded `_info` metadata from geth execution:

```shell
# In go-ethereum directory
cd tests/fuzzers/statetest

# Run the fuzzer to generate corpus with trace hashes
go-fuzz -bin=./statetest-fuzz.zip -workdir=/tmp/corpus -procs=8

# Or use existing corpus with trace embedding
./evm statetest --trace.hash /path/to/tests/*.json
```

The enhanced corpus files should have this structure:
```json
{
  "testName": {
    "_info": {
      "generatedBy": "geth/v1.14.0",
      "traceHash": "abc123...",
      "stateRoot": "0x...",
      "traceLines": 42
    },
    "env": {...},
    "pre": {...},
    "transaction": {...},
    "expect": [...]
  }
}
```

### Phase 2: Quick Validation Run

Start with a quick validation to assess the corpus:

```shell
# Quick validation (no triage, just counts)
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
  --corpus-dir=/tmp/trace-test-output/tests/ \
  --fork=Osaka \
  --workers=16
```

**Expected output:**
```
=== Cross-VM Corpus Validator ===

Corpus:  /tmp/trace-test-output/tests
Files:   52714
Fork:    Osaka
Workers: 16

[3.033s] processed: 136 (44.8/s) | passed: 134 | diverged: 2 | skipped: 0 | errors: 0
...

========================================
Cross-VM Corpus Validation Complete
========================================

Results:
  Total:    52714
  Passed:   50896
  Diverged: 1801
  Skipped:  0
  Errors:   17

Pass Rate:  96.6%
```

### Phase 3: Triage Divergences

If divergences are detected, run with `--triage` to cluster them:

```shell
# Full triage analysis
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
  --corpus-dir=/tmp/trace-test-output/tests/ \
  --fork=Osaka \
  --workers=16 \
  --triage
```

**Triage output explains the divergences:**
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

By Failure Pattern:
  UNKNOWN                         40 clusters,  1500 tests
  GAS_MISMATCH                     5 clusters,   200 tests
  PRECOMPILE_ERROR                 2 clusters,   101 tests

Top 10 Clusters (by impact):
----------------------------
#1: Cluster[54b7c078→abf995f6] size=500 type=STATE_ROOT_AND_TRACE_MISMATCH
    State root mismatches: 500/500
    Test patterns: 54b7c078fbf487f9
    Representatives:
      - 54b7c078fbf487f9_728.json
      - 54b7c078fbf487f9_518.json
      - 54b7c078fbf487f9_652.json
```

### Phase 4: Export Reports

Generate machine-readable reports for CI/CD or further analysis:

```shell
# JSON report to stdout
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
  --corpus-dir=/tmp/trace-test-output/tests/ \
  --fork=Osaka \
  --triage \
  --json \
  --quiet

# Save reports to directory
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
  --corpus-dir=/tmp/trace-test-output/tests/ \
  --fork=Osaka \
  --triage \
  --output-dir=./validation-results/
```

### Phase 5: Debug Specific Divergences

For detailed investigation, dump Besu traces for divergent tests:

```shell
# Dump traces for divergent tests
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
  --corpus-dir=/tmp/trace-test-output/tests/ \
  --fork=Osaka \
  --dump-traces \
  --output-dir=./debug-traces/

# Include filtered entries (STOP, depth=0) for complete traces
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
  --corpus-dir=/tmp/trace-test-output/tests/ \
  --fork=Osaka \
  --dump-traces \
  --include-filtered \
  --output-dir=./debug-traces/
```

Then compare traces side-by-side:
```shell
# View Besu trace for a specific divergent test
cat ./debug-traces/54b7c078fbf487f9_728.jsonl

# Compare with geth trace (if available)
diff <(jq -S . besu_trace.jsonl) <(jq -S . geth_trace.jsonl)
```

## Common Workflows

### Workflow A: CI/CD Integration

```shell
#!/bin/bash
# ci-validate.sh - Exit non-zero on divergences

./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
  --corpus-dir="${CORPUS_DIR}" \
  --fork="${FORK:-Osaka}" \
  --workers="${WORKERS:-$(nproc)}" \
  --json \
  --quiet \
  --output-dir=./ci-results/

EXIT_CODE=$?
if [ $EXIT_CODE -eq 1 ]; then
  echo "CONSENSUS DIVERGENCES DETECTED - See ci-results/validation_report.json"
fi
exit $EXIT_CODE
```

### Workflow B: Investigate a Single Test

```shell
# Validate a single file
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
  --corpus-dir=/path/to/specific_test.json \
  --fork=Osaka \
  --dump-traces \
  --include-filtered \
  --output-dir=./single-test-debug/
```

### Workflow C: Compare Forks

```shell
# Validate against multiple forks to find fork-specific bugs
for fork in Prague Osaka Cancun; do
  echo "=== Testing $fork ==="
  ./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
    --corpus-dir=/tmp/corpus/ \
    --fork=$fork \
    --quiet \
    --json > results_${fork}.json
done

# Compare results
jq -s '.[0].results as $p | .[1].results as $o |
  {prague_diverged: $p.diverged, osaka_diverged: $o.diverged}' \
  results_Prague.json results_Osaka.json
```

### Workflow D: Subset Testing

```shell
# Test a random sample first
mkdir -p /tmp/sample-corpus
ls /path/to/corpus/*.json | shuf | head -1000 | xargs -I{} cp {} /tmp/sample-corpus/

./testfuzz/build/install/BesuFuzz/bin/BesuFuzz validate-corpus \
  --corpus-dir=/tmp/sample-corpus/ \
  --fork=Osaka \
  --triage
```

## Understanding Triage Output

### Divergence Types

| Type | Meaning | Severity |
|------|---------|----------|
| `STATE_ROOT_AND_TRACE_MISMATCH` | Both trace and final state differ | Critical |
| `STATE_ROOT_ONLY_MISMATCH` | Same trace but different final state | High |
| `TRACE_ONLY_MISMATCH` | Different execution path, same result | Medium |
| `ERROR` | Execution error occurred | Variable |

### Failure Patterns

| Pattern | Likely Cause |
|---------|--------------|
| `GAS_MISMATCH` | Gas calculation difference |
| `PRECOMPILE_ERROR` | Precompile implementation differs |
| `CREATE_ERROR` | Contract creation logic differs |
| `STACK_ERROR` | Stack handling difference |
| `EOF_ERROR` | EOF validation/execution differs |
| `UNKNOWN` | Requires manual investigation |

### Impact Score

Clusters are ranked by impact score (0-1):
- **Severity weight (50%)**: STATE_ROOT > ERROR > TRACE_ONLY
- **Size weight (30%)**: More affected tests = higher impact
- **Uniqueness weight (20%)**: More state root variants = more complex

### Interpreting Compression Ratio

```
Compression ratio: 38.3x
```
This means 1,801 divergences reduced to 47 clusters - you only need to investigate ~47 likely distinct bugs, not 1,801 individual failures.

## CLI Reference

```
Usage: BesuFuzz validate-corpus [OPTIONS]

Options:
  --corpus-dir=<dir>      Directory with corpus files (required)
  --fork=<name>           EVM fork: Prague, Osaka, Cancun, etc. (default: Prague)
  -w, --workers=<n>       Worker threads (default: CPU count)
  --triage                Cluster divergences by likely root cause
  --dump-traces           Save Besu traces for divergent tests
  --include-filtered      Include STOP/depth=0 in trace dumps
  -o, --output-dir=<dir>  Output directory for reports/traces
  --json                  Output JSON report
  -q, --quiet             Suppress progress output
  -h, --help              Show help

Exit Codes:
  0 - All tests passed
  1 - Divergences detected
  2 - Errors occurred
```

## Troubleshooting

### "No .json files found in corpus directory"
- Verify the corpus directory path
- Ensure files have `.json` extension
- Check file permissions

### High error count
- Check if corpus files have valid `_info` metadata
- Verify the fork name matches the corpus target fork
- Look at error messages in the output

### Slow validation
- Increase workers: `--workers=32`
- Use SSD storage for corpus
- Ensure JVM has enough heap: `JAVA_OPTS="-Xmx8g"`

### Memory issues
- Reduce workers: `--workers=4`
- Process corpus in batches
- Use `--quiet` to reduce output buffering
