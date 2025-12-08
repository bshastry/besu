# Cross-VM Metadata Specification

## Version: 1.0 (2025-12-08)

This document specifies the standard format for embedding cross-VM consensus verification metadata in Ethereum state test JSON files, following EEST conventions.

## Overview

When fuzzing or testing across multiple Ethereum clients (geth, Besu, Nethermind, etc.), we need to embed metadata in state test files to enable:
- Trace hash comparison for consensus verification
- Identification of which client generated the test
- Version tracking for reproducibility

## Format Specification

### Location

Metadata MUST be placed inside the `_info` field within each test object, following the official EEST/ethereum-tests convention:

```json
{
  "testName": {
    "_info": {
      "comment": "Cross-VM consensus verification test",
      "generatedBy": "geth",
      "traceHash": "abc123def456...",
      "stateRoot": "0x1234...",
      "traceLines": 42,
      "crossvmVersion": "1.0",
      "generatedAt": "2025-12-08T12:00:00Z"
    },
    "env": { ... },
    "pre": { ... },
    "transaction": { ... },
    "post": { ... }
  }
}
```

### Why `_info` Inside Test Object?

1. **EEST Standard**: The `_info` field is the official convention in ethereum-tests
2. **Parser Compatibility**: All clients ignore unknown fields inside test objects
3. **Self-Contained**: Each test carries its own metadata
4. **Multi-Test Support**: Works correctly with files containing multiple tests

### DO NOT Use Top-Level Metadata

```json
// WRONG - Do not do this!
{
  "testName": { ... },
  "_crossvm": { ... }    // Gets parsed as a broken test entry
}
```

## Field Definitions

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `generatedBy` | string | Client that generated this test: `"geth"`, `"besu"`, `"nethermind"`, `"erigon"`, `"revm"`, `"evmone"` |
| `traceHash` | string | MD5 hash (hex) of normalized trace lines + stateRoot |
| `stateRoot` | string | Expected post-execution state root (0x-prefixed hex) |
| `crossvmVersion` | string | Version of this spec: `"1.0"` |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `comment` | string | Human-readable description |
| `traceLines` | integer | Number of trace lines included in hash |
| `generatedAt` | string | ISO 8601 timestamp of generation |
| `version` | string | Client version string |
| `fork` | string | Fork name used for execution (e.g., `"Cancun"`, `"Prague"`) |

### Standard EEST Fields (Optional)

These fields follow existing ethereum-tests conventions:

| Field | Type | Description |
|-------|------|-------------|
| `fixture-format` | string | Always `"state_test"` for state tests |
| `filling-rpc-server` | string | Client/version used (e.g., `"Geth-1.14.12"`) |
| `source` | string | Path to source file |
| `sourceHash` | string | SHA256 hash of source |

## Trace Hash Computation

The `traceHash` is computed as:

```
traceHash = MD5(normalized_trace_line_1 + "\n" +
                normalized_trace_line_2 + "\n" +
                ... +
                stateRoot_line + "\n")
```

### Normalized Trace Line Format

Each trace line is JSON with these fields in exact order:

```json
{"depth":1,"pc":0,"gas":100000,"op":"0x60","opName":"PUSH1","stack":[]}
```

| Field | Type | Format |
|-------|------|--------|
| `depth` | integer | Decimal, call depth (1 = top level) |
| `pc` | integer | Decimal, program counter |
| `section` | integer | Decimal, EOF section (omit if 0) |
| `functionDepth` | integer | Decimal, EOF function depth (omit if 0) |
| `gas` | integer | Decimal, gas remaining |
| `op` | string | Hex opcode, 0x-prefixed, 2 digits, zero-padded |
| `opName` | string | Opcode mnemonic |
| `stack` | array | Last 6 stack items as hex strings |

### State Root Line Format

```json
{"stateRoot":"0x1234567890abcdef..."}
```

### Filtering Rules

Before hashing, filter out:
- Lines with `depth == 0` (pre-execution)
- `STOP` opcode (0x00) entries
- Duplicate entries (same `pc` + `depth` + `functionDepth`)

## Example

### Complete State Test with Cross-VM Metadata

```json
{
  "crossvm_add_test": {
    "_info": {
      "comment": "Simple ADD operation for cross-VM verification",
      "fixture-format": "state_test",
      "generatedBy": "geth",
      "version": "1.14.12-unstable",
      "generatedAt": "2025-12-08T12:00:00Z",
      "traceHash": "554721540910426df028adc736f6c7f1",
      "stateRoot": "0x34e719c9b54bb138793c8503faf8e7c09c9e0dc61c26e912cbdbde0fd106e3f7",
      "traceLines": 6,
      "crossvmVersion": "1.0"
    },
    "env": {
      "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
      "currentDifficulty": "0x20000",
      "currentGasLimit": "0xffffffff",
      "currentNumber": "0x01",
      "currentTimestamp": "0x03e8",
      "previousHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "currentBaseFee": "0x0a"
    },
    "pre": {
      "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
        "balance": "0xffffffff",
        "code": "0x",
        "nonce": "0x00",
        "storage": {}
      },
      "0xcccccccccccccccccccccccccccccccccccccccc": {
        "balance": "0x00",
        "code": "0x6001600101600055",
        "nonce": "0x00",
        "storage": {}
      }
    },
    "transaction": {
      "data": ["0x"],
      "gasLimit": ["0x100000"],
      "gasPrice": "0x0a",
      "nonce": "0x00",
      "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
      "to": "0xcccccccccccccccccccccccccccccccccccccccc",
      "value": ["0x00"]
    },
    "post": {
      "London": [
        {
          "hash": "0x34e719c9b54bb138793c8503faf8e7c09c9e0dc61c26e912cbdbde0fd106e3f7",
          "indexes": {"data": 0, "gas": 0, "value": 0}
        }
      ]
    }
  }
}
```

## Cross-VM Verification Protocol

### When Loading Corpus Entry

1. Parse JSON and extract `_info` field from test object
2. Check if `generatedBy` differs from current client
3. If different client:
   - Execute test with trace normalization
   - Compute `traceHash`
   - Compare with stored `traceHash`
   - If mismatch: **CONSENSUS DIVERGENCE DETECTED**

### When Saving Corpus Entry

1. Execute test with trace normalization
2. Compute `traceHash` and capture `stateRoot`
3. Embed `_info` inside test object with all required fields
4. Save to corpus directory

## Implementation Notes

### Geth (Go)

```go
// Reading _info from test
type TestInfo struct {
    GeneratedBy    string `json:"generatedBy"`
    TraceHash      string `json:"traceHash"`
    StateRoot      string `json:"stateRoot"`
    CrossVMVersion string `json:"crossvmVersion"`
    // ... other fields
}

// Parse from raw JSON
var raw map[string]json.RawMessage
json.Unmarshal(testJSON, &raw)
for testName, testData := range raw {
    var testObj map[string]json.RawMessage
    json.Unmarshal(testData, &testObj)
    if infoRaw, ok := testObj["_info"]; ok {
        var info TestInfo
        json.Unmarshal(infoRaw, &info)
        // Use info...
    }
}
```

### Besu (Java)

```java
// _info is automatically ignored by @JsonIgnoreProperties(ignoreUnknown = true)
// To read it, parse the raw JSON separately:

ObjectMapper mapper = new ObjectMapper();
JsonNode root = mapper.readTree(testJson);
for (Iterator<String> it = root.fieldNames(); it.hasNext(); ) {
    String testName = it.next();
    JsonNode testNode = root.get(testName);
    JsonNode infoNode = testNode.get("_info");
    if (infoNode != null) {
        String generatedBy = infoNode.get("generatedBy").asText();
        String traceHash = infoNode.get("traceHash").asText();
        // Use metadata...
    }
}
```

## Changelog

### Version 1.0 (2025-12-08)
- Initial specification
- Adopted EEST `_info` convention
- Defined required and optional fields
- Specified trace hash computation
- Added implementation examples for geth and Besu
