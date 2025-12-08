# Cross-VM Debug Mode

This document describes the debug mode for investigating EVM trace divergences between Besu and other Ethereum clients (primarily geth).

## Overview

The cross-VM trace comparison system produces MD5 hashes of normalized execution traces. When traces diverge between clients, the debug mode helps identify exactly which trace entries differ and why.

## DumpTraceWriter

The `DumpTraceWriter` class outputs trace lines to a JSONL file for manual inspection and comparison.

### Usage

```java
// Create a dump writer with filtered entry logging enabled
try (DumpTraceWriter dumpWriter = new DumpTraceWriter("trace.jsonl", true)) {
    // Write metadata header
    dumpWriter.writeMeta("besu", "24.12.0", "Prague", inputHash, testName);

    // Create normalizer with dump writer
    TraceNormalizer normalizer = new TraceNormalizer(dumpWriter);

    // Process trace entries
    normalizer.processLog(log);

    // Finish and get hash
    byte[] hash = normalizer.finish(stateRoot);
}
```

### With NormalizingOperationTracer

```java
DumpTraceWriter dumpWriter = new DumpTraceWriter("trace.jsonl", true);
NormalizingOperationTracer tracer = new NormalizingOperationTracer(dumpWriter);

// Execute transaction with tracer
// ...

TracingResult result = tracer.finish(stateRoot);
dumpWriter.close();
```

## Output Format (JSONL)

The dump file contains one JSON object per line:

```jsonl
{"_meta":{"client":"besu","version":"24.12.0","fork":"Prague","inputHash":"abc123","testName":"Test_d0g0v0","timestamp":"2025-12-08T12:00:00Z","normalizerVersion":"1"}}
{"depth":1,"pc":0,"gas":100000000,"op":"0x60","opName":"PUSH1","stack":[]}
{"_filtered":{"reason":"DEPTH_ZERO","depth":0,"pc":5,"op":"0x60","opName":"PUSH1"}}
{"depth":1,"pc":2,"gas":99999997,"op":"0x01","opName":"ADD","stack":["0x1","0x2"]}
{"_filtered":{"reason":"STOP_OPCODE","depth":1,"pc":100,"op":"0x00","opName":"STOP"}}
{"stateRoot":"0xabcdef1234567890"}
{"_result":{"traceHash":"abc123...","traceLines":3,"finalLineHash":"xyz789..."}}
```

## Line Types

### Metadata Header (`_meta`)

The first line contains metadata about the trace:

| Field | Description |
|-------|-------------|
| `client` | Client name (besu, geth, nethermind) |
| `version` | Client version string |
| `fork` | Ethereum fork (London, Paris, Prague, etc.) |
| `inputHash` | MD5 hash of the input test JSON |
| `testName` | Name of the specific subtest |
| `timestamp` | ISO 8601 timestamp |
| `normalizerVersion` | Version of the normalizer algorithm (currently "1") |

### Trace Lines

Normal trace entries contain:

| Field | Description |
|-------|-------------|
| `depth` | Call stack depth (1-indexed) |
| `pc` | Program counter |
| `gas` | Gas remaining before execution |
| `op` | Opcode in hex format (0x00-0xff) |
| `opName` | Human-readable opcode name |
| `stack` | Last 6 stack items, bottom to top |
| `section` | (Optional) EOF section number |
| `functionDepth` | (Optional) EOF function depth |

### Filtered Entries (`_filtered`)

When `includeFiltered=true`, filtered entries are logged with their reason:

| Reason Code | Description |
|-------------|-------------|
| `STOP_OPCODE` | STOP opcode (0x00) filtered |
| `DEPTH_ZERO` | depth=0 entry filtered (not a real opcode) |
| `DUPLICATE` | Duplicate PC+depth+functionDepth filtered |

### State Root

The state root is included as the final trace entry:
```json
{"stateRoot":"0x..."}
```

### Result Footer (`_result`)

The last line contains the trace result:

| Field | Description |
|-------|-------------|
| `traceHash` | MD5 hash of all normalized trace lines |
| `traceLines` | Number of lines in the hash (includes stateRoot) |
| `finalLineHash` | MD5 hash of just the final line (helps identify stateRoot vs trace divergence) |

## Comparing Traces

### Generate Traces for Both Clients

```bash
# Generate Besu trace
java -jar besu-testfuzz.jar state-test --dump-trace=besu_trace.jsonl test.json

# Generate geth trace
./evm statetest --dump-trace=geth_trace.jsonl test.json
```

### Quick Diff

```bash
# Compare traces line-by-line
diff besu_trace.jsonl geth_trace.jsonl

# Use jq for pretty comparison
jq -c '.' besu_trace.jsonl > besu_formatted.jsonl
jq -c '.' geth_trace.jsonl > geth_formatted.jsonl
diff besu_formatted.jsonl geth_formatted.jsonl
```

### Identify First Divergence

```bash
# Show first differing line with context
diff -u besu_trace.jsonl geth_trace.jsonl | head -20
```

## Common Divergence Causes

1. **Gas calculation differences**: Look for gas values that differ
2. **Stack representation**: Ensure both use minimal hex representation (0xf not 0x0f)
3. **Pre vs post execution**: Traces must capture state BEFORE opcode executes
4. **STOP filtering**: Both should filter STOP (0x00) opcodes
5. **Depth-0 filtering**: Both should filter depth=0 entries
6. **State root differences**: If only stateRoot differs, the execution result differs (not trace format)

## Implementation Notes

The `DumpTraceWriter` is designed to be compatible with geth's equivalent implementation in `tests/fuzzers/statetest/normalizer.go`. Both implementations:

1. Use JSONL format (one JSON object per line)
2. Include the same metadata fields
3. Use the same filter reason codes
4. Produce identical trace line formats

This compatibility enables direct `diff` comparison of trace dumps from both clients.
