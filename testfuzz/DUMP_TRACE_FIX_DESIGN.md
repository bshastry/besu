# BesuFuzz dump-trace Fix Design: Handling Transaction Construction Failures

## Problem Statement

`BesuFuzz dump-trace` produces no output for ~20 tests in the corpus, while `geth statetest-trace dump` correctly outputs a state root and trace result for the same tests.

## Root Cause Analysis

### Investigation Summary

Initial hypothesis was fork mismatch (BesuFuzz defaults to Prague, test has Cancun), but this was ruled out because:
- BesuFuzz's `StateTestExecutor.executeWithTracingAndDump()` iterates ALL forks in `finalStateSpecs`
- Most Cancun exception tests work correctly

The actual issue was discovered by comparing working vs non-working exception tests:

| Test | Fork | Exception Type | BesuFuzz Output |
|------|------|---------------|-----------------|
| `000e88409b1c2917.json` | Cancun | `INTRINSIC_GAS_TOO_LOW` | 2 lines (works) |
| `235a84eef39e3276.json` | Cancun | `TYPE_3_TX_INVALID_BLOB_VERSIONED_HASH` | Empty (broken) |

### Key Difference: Transaction Structure

**Working test** (gas too low):
```json
{
  "maxFeePerBlobGas": null,
  "blobVersionedHashes": null
}
```

**Non-working test** (invalid blob hashes):
```json
{
  "maxFeePerBlobGas": "0x01",
  "blobVersionedHashes": [
    "0x0100000000000000000000000000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000000000000000000000000000002"
  ]
}
```

The second blob hash starts with `0x00` instead of `0x01` (invalid KZG commitment version byte).

### Code Path Analysis

In `GeneralStateTestCaseEipSpec.java:96-105`:
```java
public Transaction getTransaction(final int txIndex) {
  try {
    return transactionSuppliers.get(txIndex).get();
  } catch (RuntimeException re) {
    // some tests specify invalid transactions. We throw exceptions in
    // GeneralStateTests but they are encoded in BlockchainTests, so we
    // can skip them as invalid (since the point of the tests is to reject
    // invalid transactions).
    return null;
  }
}
```

When constructing a Type 3 (blob) transaction with invalid versioned hashes, Besu throws a `RuntimeException` during construction, and `getTransaction()` returns `null`.

In `StateTestExecutor.executeSpecWithTracing()` (line 456-458):
```java
Transaction transaction = spec.getTransaction(0);
if (transaction == null) {
  return null;  // <-- Silently produces no output!
}
```

## Two Types of Exception Tests

### Type 1: Transaction Construction Fails
- **Cause**: Invalid transaction fields that fail during parsing/construction
- **Examples**: Invalid blob versioned hashes, malformed signatures
- **Behavior**: `spec.getTransaction(0)` returns `null`
- **BesuFuzz**: No output (bug)
- **Geth**: Outputs pre-state root with `traceLines: 1`

### Type 2: Transaction Constructed but Rejected
- **Cause**: Valid transaction structure, but fails validation checks
- **Examples**: Intrinsic gas too low, insufficient balance
- **Behavior**: `spec.getTransaction(0)` returns valid Transaction, processor rejects it
- **BesuFuzz**: Outputs 2 lines (stateRoot, _result) - works correctly
- **Geth**: Same output

## Corpus Statistics

- Total tests with `expectException`: **2303**
- Tests affected by this bug: **~20** (transaction construction failures)

## Fix Design

### Changes Required

#### 1. `StateTestExecutor.java` - Handle null transactions

Update `executeSpecWithTracing()` to handle transaction construction failures:

```java
private String executeSpecWithTracing(
    final GeneralStateTestCaseEipSpec spec, final OperationTracer tracer) {
  // ... existing null checks ...

  Transaction transaction = spec.getTransaction(0);

  // Handle transaction construction failure
  if (transaction == null) {
    // Transaction construction failed (e.g., invalid blob versioned hashes)
    // For exception tests, we still need to output the pre-state root
    ReferenceTestWorldState initialWorldState = spec.getInitialWorldState();
    if (initialWorldState != null && spec.getExpectException() != null) {
      // Return pre-state root since no state changes occurred
      return initialWorldState.rootHash().toHexString();
    }
    return null;
  }

  // ... rest of existing code ...
}
```

#### 2. `StateTestExecutor.java` - Add fork auto-detection helper

```java
/**
 * Detects the first available fork from a state test's post section.
 *
 * @param jsonData the state test JSON bytes
 * @return the first fork name found, or defaultFork if none
 */
public String detectForkFromTest(final byte[] jsonData) {
  try {
    Map<String, GeneralStateTestCaseSpec> stateTests =
        objectMapper.readValue(jsonData, stateTestType);
    for (GeneralStateTestCaseSpec spec : stateTests.values()) {
      Map<String, List<GeneralStateTestCaseEipSpec>> finalStateSpecs = spec.finalStateSpecs();
      if (finalStateSpecs != null && !finalStateSpecs.isEmpty()) {
        return finalStateSpecs.keySet().iterator().next();
      }
    }
  } catch (Exception e) {
    // Fall through to default
  }
  return defaultFork;
}
```

#### 3. `DumpTraceSubCommand.java` - Auto-detect fork and write metadata

```java
@Option(
    names = {"--fork"},
    description = "EVM fork to use (auto-detected from test if not specified)")
private String fork;  // Remove defaultValue, null means auto-detect

@Override
public void run() {
  // ... existing validation ...

  byte[] jsonData = Files.readAllBytes(testFile.toPath());

  // Create executor (needed for fork detection)
  StateTestExecutor executor = new StateTestExecutor();

  // Auto-detect fork if not specified
  String effectiveFork = fork;
  if (effectiveFork == null) {
    effectiveFork = executor.detectForkFromTest(jsonData);
  }

  // Compute input hash for metadata
  String inputHash = computeMD5(jsonData);
  String testName = extractTestName(jsonData);  // Helper to get first test name

  // Create output writer with detected fork
  DumpTraceWriter dumpWriter = createDumpWriter(effectiveFork);

  // Write metadata header BEFORE execution
  dumpWriter.writeMeta("besu", getVersion(), effectiveFork, inputHash, testName);

  // Execute with tracing
  TracingResult result = executor.executeWithTracingAndDump(jsonData, dumpWriter);

  // Result writing is handled by TraceNormalizer.finish()
  dumpWriter.close();
}
```

#### 4. `executeWithTracingAndDump()` - Ensure output for all cases

Update to always produce output, even when no EVM execution occurs:

```java
public TracingResult executeWithTracingAndDump(
    final byte[] jsonData, final DumpTraceWriter dumpWriter) {
  // ... existing parsing ...

  NormalizingOperationTracer tracer = new NormalizingOperationTracer(dumpWriter);
  String finalStateRoot = null;
  boolean anySpecProcessed = false;

  for (/* each spec */) {
    try {
      String stateRoot = executeSpecWithTracing(eipSpec, tracer);
      if (stateRoot != null) {
        finalStateRoot = stateRoot;
        anySpecProcessed = true;
      }
    } catch (Exception e) {
      // ... error handling ...
    }
  }

  // Always finish tracing if we have a state root
  if (finalStateRoot != null) {
    return tracer.finish(finalStateRoot);
  }

  // No specs produced output - return empty result with proper structure
  return new TracingResult(null, null, 0);
}
```

### Expected Behavior After Fix

| Scenario | Current Output | Expected Output |
|----------|---------------|-----------------|
| Normal test | Trace + stateRoot + _result | No change |
| Exception (tx rejected) | stateRoot + _result | No change |
| Exception (tx construction fails) | **Empty** | _meta + stateRoot + _result |
| Unsupported fork | Empty | Empty (acceptable) |

### Geth Output Reference

For comparison, geth's output for `235a84eef39e3276.json`:
```jsonl
{"_meta":{"client":"geth","version":"...","fork":"Cancun","inputHash":"...","testName":"...","timestamp":"...","normalizerVersion":"1"}}
{"stateRoot":"0x25bd2b115ac0f0916a082304b106d470b31d6ccbb75ed7a45676369a5317ccd4"}
{"_result":{"traceHash":"235a84eef39e327631a84344390aec05","traceLines":1,"finalLineHash":"..."}}
```

Note: `traceLines: 1` means only the stateRoot line contributes to the trace hash.

## Files to Modify

1. `testfuzz/src/main/java/org/hyperledger/besu/testfuzz/DumpTraceSubCommand.java`
   - Remove `defaultValue = "Prague"` from `--fork` option
   - Add fork auto-detection logic
   - Write `_meta` header before execution
   - Add helper methods for input hash and test name extraction

2. `testfuzz/src/main/java/org/hyperledger/besu/testfuzz/StateTestExecutor.java`
   - Add `detectForkFromTest()` method
   - Update `executeSpecWithTracing()` to return pre-state root for null transactions with expected exceptions
   - Ensure `executeWithTracingAndDump()` always produces valid output structure

## Testing Plan

1. Verify fix with `235a84eef39e3276.json` (blob tx with invalid versioned hashes)
2. Verify existing tests still work (`00091e20ae0b3918.json`, `000e88409b1c2917.json`)
3. Run comparison against all ~2303 exception tests
4. Ensure trace hashes match between BesuFuzz and geth for fixed tests

---

## Triage Integration (Implemented)

The divergence triage system has been updated to recognize and properly categorize transaction construction failures.

### New Failure Patterns Added

In `DivergenceCluster.FailurePattern`:

```java
TX_CONSTRUCTION_FAILURE  // Transaction cannot be parsed/built (known limitation)
BLOB_TX_ERROR           // Blob transaction specific errors
```

### Detection Logic

The `DivergenceAnalyzer.isTxConstructionFailure()` method detects this pattern by:

1. **Null trace signature**: `actualTraceHash == null && expectedTraceHash != null`
2. **Trace line count**: All members have 0 actual lines, but expected has 1 line (just stateRoot)
3. **Test name patterns**: Contains blob/type_3/eip4844 AND invalid/exception keywords

### Console Output Enhancement

When TX_CONSTRUCTION_FAILURE clusters are detected, the triage report now shows:

```
By Failure Pattern:
  TX_CONSTRUCTION_FAILURE          1 clusters,    20 tests [KNOWN LIMITATION]
  BLOB_TX_ERROR                    2 clusters,    15 tests [CHECK TX VALIDITY]

NOTE: TX_CONSTRUCTION_FAILURE divergences are a known limitation.
  These occur when transaction construction fails (e.g., invalid blob
  versioned hashes). Besu's getTransaction() returns null, producing no
  trace output, while geth outputs the pre-state root. This is NOT a
  consensus bug - both clients correctly reject the invalid transaction.
  Affected tests: 20 (can be safely ignored for consensus validation)
```

### Files Modified for Triage

1. `testfuzz/src/main/java/org/hyperledger/besu/testfuzz/validator/DivergenceCluster.java`
   - Added `TX_CONSTRUCTION_FAILURE` and `BLOB_TX_ERROR` to `FailurePattern` enum

2. `testfuzz/src/main/java/org/hyperledger/besu/testfuzz/validator/DivergenceAnalyzer.java`
   - Added pattern matchers for tx construction and blob tx errors
   - Added `isTxConstructionFailure()` detection method
   - Updated `detectPattern()` to check for new patterns first
   - Enhanced console summary to annotate known limitations
