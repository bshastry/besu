# Parallel Coverage-Guided Fuzzer Implementation Prompt

**STATUS: IMPLEMENTED** (2024-12-08)

The parallel coverage-guided fuzzer has been fully implemented and tested.

---

## Implementation Status

All components have been implemented:

- [x] `CorpusEntry.java` - AFL-style corpus entry with energy scheduling
- [x] `InputQueue.java` - Thread-safe priority queue with deduplication
- [x] `CoverageTracker.java` - Thread-safe JaCoCo integration
- [x] `CrashManager.java` - Thread-safe crash saving with deduplication
- [x] `FuzzWorker.java` - Worker threads with thread-local components
- [x] `CoverageGuidedFuzzer.java` - Main orchestrator with virtual threads
- [x] `StateTestFuzzSubCommand.java` - Added `--parallel-guided` CLI flag

### Test Results (Osaka fork, 4 workers, 30s)

```
Total executions: 33,196 (~1,106 exec/s)
Coverage edges: 2,749 (205 classes)
Coverage hits: 172 interesting inputs
Queue growth: 54,861 → 55,029 (+168 new entries)
Crashes: 0
```

---

## Context

You are implementing a coverage-guided parallel fuzzer for Besu's EVM state test fuzzing. The architecture has been designed and documented in `testfuzz/PARALLEL_FUZZER_ARCHITECTURE.md`.

**Current branch**: `feature/coverage-guided-parallel-fuzzer`

**Key problem being solved**: The current fuzzer has two modes that are mutually exclusive:
1. Single-threaded with JaCoCo coverage guidance (slow but smart)
2. Multi-threaded without coverage guidance (fast but dumb)

The new implementation combines both: **multi-threaded fuzzing with shared coverage guidance**.

## Implementation Task

Implement the parallel coverage-guided fuzzer using an agentic workflow. Follow the architecture document exactly. Create the following components in order:

### Phase 1: Core Data Structures

1. **`CorpusEntry.java`** (`testfuzz/src/main/java/org/hyperledger/besu/testfuzz/parallel/`)
   - Input metadata: data, hash, energy, mutationCount, discoveryTime
   - Energy scheduling: boost on new coverage, decay after dry mutations
   - Comparable for priority queue ordering (higher energy first)
   - See architecture doc section 3.2

2. **`InputQueue.java`**
   - `PriorityBlockingQueue<CorpusEntry>` for thread-safe priority access
   - `ConcurrentHashMap.newKeySet()` for O(1) deduplication by SHA-256 hash
   - Methods: `addInitial()`, `addFromMutation()`, `poll()`, `requeue()`
   - See architecture doc section 3.2

### Phase 2: Coverage Tracking

3. **`CoverageTracker.java`**
   - Thread-safe JaCoCo integration using `ReentrantReadWriteLock`
   - `ConcurrentHashMap<String, int[]>` for coverage bitmap (className → probeHits)
   - `checkNewCoverage()` returns `CoverageResult` with newEdges count
   - Filter classes by `guidanceRegexp` pattern
   - See architecture doc section 3.1

### Phase 3: Worker and Crash Management

4. **`CrashManager.java`**
   - Thread-safe crash saving with deduplication
   - `ConcurrentHashMap.newKeySet()` for seen crash hashes
   - Saves both `.json` (test data) and `.txt` (metadata) files
   - See architecture doc section 3.4

5. **`FuzzWorker.java`**
   - Implements `Runnable` for virtual thread execution
   - Thread-local `StateTestExecutor` and `CombinedMutationStrategy`
   - Main loop: poll → mutate → execute → checkCoverage → maybe add to queue → requeue
   - See architecture doc section 3.3

### Phase 4: Orchestrator and CLI

6. **`CoverageGuidedFuzzer.java`**
   - Builder pattern for configuration
   - Lifecycle: initialize → loadCorpus → startWorkers → monitor → shutdown
   - Uses `Executors.newVirtualThreadPerTaskExecutor()` (Java 21+)
   - Progress reporting every 5 seconds
   - See architecture doc section 3.5

7. **Update `StateTestFuzzSubCommand.java`**
   - Add `--parallel-guided` CLI flag
   - When both `--parallel-guided` and `--guidance-regexp` are set, use new fuzzer
   - See architecture doc section 6.1

### Phase 5: Testing and Validation

8. **Unit tests** for:
   - `CorpusEntry`: energy calculations, compareTo ordering
   - `InputQueue`: deduplication, priority ordering, thread safety
   - `CoverageTracker`: bitmap updates, new edge detection

9. **Integration test**:
   - Run with 2 workers for 10 seconds
   - Verify coverage is shared (both workers contribute to same bitmap)
   - Verify interesting inputs are shared (queue grows)

## Key Implementation Details

### Energy Constants (from AFL)
```java
public static final int INITIAL_ENERGY = 1;
public static final int NEW_COVERAGE_ENERGY_BOOST = 16;
public static final int MAX_ENERGY = 64;
public static final int DECAY_THRESHOLD = 100;
```

### Thread Safety Summary
| Component | Mechanism |
|-----------|-----------|
| Coverage bitmap | `ReentrantReadWriteLock` |
| Input queue | `PriorityBlockingQueue` |
| Hash deduplication | `ConcurrentHashMap.newKeySet()` |
| Worker state | Thread-local (no sharing) |
| Original corpus | Immutable `List<byte[]>` |

### JaCoCo Integration
```java
// Get agent singleton (thread-safe)
Class<?> rtClass = Class.forName("org.jacoco.agent.rt.RT");
Object agent = rtClass.getMethod("getAgent").invoke(null);
Method getDataMethod = agent.getClass().getMethod("getExecutionData", boolean.class);

// Get cumulative coverage (thread-safe read)
byte[] data = (byte[]) getDataMethod.invoke(agent, false);  // false = don't reset
```

### Package Structure
```
testfuzz/src/main/java/org/hyperledger/besu/testfuzz/
├── parallel/
│   ├── CorpusEntry.java
│   ├── InputQueue.java
│   ├── CoverageTracker.java
│   ├── CrashManager.java
│   ├── FuzzWorker.java
│   └── CoverageGuidedFuzzer.java
├── statetest/
│   └── (existing mutation strategies)
└── StateTestFuzzSubCommand.java (modify)
```

## Verification Steps

After implementation, verify with:

```bash
# Build
./gradlew :testfuzz:compileJava

# Run with parallel coverage guidance
./testfuzz/build/install/BesuFuzz/bin/BesuFuzz state-test-fuzz \
  --corpus-dir=/path/to/goevmlab/corpus \
  --fork=Prague \
  --duration=30s \
  --workers=4 \
  --parallel-guided \
  --guidance-regexp="org.hyperledger.besu.evm.*"
```

Expected output should show:
- Multiple workers contributing to shared coverage
- Queue growing as interesting inputs are discovered
- Coverage edges increasing over time
- Higher exec/s than single-threaded guided mode

## References

- Architecture document: `testfuzz/PARALLEL_FUZZER_ARCHITECTURE.md`
- Existing mutation strategies: `testfuzz/src/main/java/org/hyperledger/besu/testfuzz/statetest/`
- Existing single-threaded fuzzer: `testfuzz/src/main/java/org/hyperledger/besu/testfuzz/javafuzz/Fuzzer.java`
- AFL technical details: https://lcamtuf.coredump.cx/afl/technical_details.txt

## Notes

- Use `java-refactoring-expert` agent for code review after each phase
- Run `./gradlew spotlessApply` before committing
- Commit after each phase with descriptive messages
- The architecture document has full pseudo-code for all components
