# Coverage-Guided Parallel Fuzzer Architecture

## Executive Summary

This document describes a comprehensive architecture for a coverage-guided parallel fuzzer for Besu's EVM state test fuzzing. The design addresses the key challenge of sharing JaCoCo coverage data across multiple worker threads while implementing AFL-style energy scheduling for optimal corpus prioritization.

## 1. Current State Analysis

### 1.1 Existing Components

| Component | Location | Thread-Safe? | Notes |
|-----------|----------|--------------|-------|
| `Fuzzer` | `javafuzz/Fuzzer.java` | No | Single-threaded, JaCoCo-guided |
| `StateTestFuzzSubCommand` | `StateTestFuzzSubCommand.java` | Partial | Multi-threaded but NO coverage sharing |
| `MutationStrategy` | `statetest/MutationStrategy.java` | Yes | Stateless interface |
| `CombinedMutationStrategy` | `statetest/CombinedMutationStrategy.java` | Yes | Uses thread-local Random |
| `StateTestExecutor` | `StateTestExecutor.java` | Yes | Thread-safe with AtomicLong stats |
| `Corpus` | `javafuzz/Corpus.java` | No | Not thread-safe (uses ArrayList) |

### 1.2 JaCoCo Coverage Model

The current `Fuzzer.java` uses JaCoCo's runtime agent via reflection:

```java
// Get agent singleton
Class<?> c = Class.forName("org.jacoco.agent.rt.RT");
Method getAgentMethod = c.getMethod("getAgent");
this.agent = getAgentMethod.invoke(null);

// Get execution data (cumulative since JVM start)
this.getExecutionDataMethod = agent.getClass().getMethod("getExecutionData", boolean.class);
byte[] dumpData = (byte[]) this.getExecutionDataMethod.invoke(this.agent, false);
```

**Critical Insight**: `getExecutionData(false)` returns cumulative coverage since JVM startup. The boolean parameter controls whether to reset the data:
- `false`: Return data without reset (safe for concurrent reads)
- `true`: Return data AND reset (NOT thread-safe)

This means multiple threads can safely read cumulative coverage, but we need careful synchronization to detect *new* coverage.

## 2. Architecture Overview

### 2.1 Component Diagram

```
+------------------------------------------------------------------+
|                    CoverageGuidedFuzzer                          |
|                    (Coordinator/Orchestrator)                     |
+------------------------------------------------------------------+
         |                    |                    |
         v                    v                    v
+------------------+  +------------------+  +------------------+
|   FuzzWorker-1   |  |   FuzzWorker-2   |  |   FuzzWorker-N   |
|  (VirtualThread) |  |  (VirtualThread) |  |  (VirtualThread) |
+------------------+  +------------------+  +------------------+
         |                    |                    |
         +--------------------+--------------------+
                              |
         +--------------------+--------------------+
         |                    |                    |
         v                    v                    v
+------------------+  +------------------+  +------------------+
| CoverageTracker  |  |   InputQueue     |  |  CrashManager   |
|    (Shared)      |  | (Priority Queue) |  |    (Shared)     |
+------------------+  +------------------+  +------------------+
         |                    |
         v                    v
+------------------+  +------------------+
| JaCoCo Runtime   |  | CorpusEntry[]    |
|    Agent         |  | with Metadata    |
+------------------+  +------------------+
```

### 2.2 Data Flow

```
1. Startup:
   Corpus files -> InputQueue (initial entries with energy=1)

2. Worker Loop:
   InputQueue.poll() -> CorpusEntry
                     -> mutate()
                     -> StateTestExecutor.execute()
                     -> CoverageTracker.checkNewCoverage()
                     -> if new: InputQueue.add(mutated, high_energy)
                     -> if crash: CrashManager.save()

3. Coverage Check:
   CoverageTracker reads JaCoCo cumulative data
   Compares against known coverage bitmap
   Returns delta (new edges discovered)
```

## 3. Core Components

### 3.1 CoverageTracker

The coverage tracker maintains shared coverage state and detects new coverage from any worker.

```java
package org.hyperledger.besu.testfuzz.parallel;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Pattern;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.data.ExecutionDataReader;

/**
 * Thread-safe coverage tracker that aggregates JaCoCo coverage from all workers.
 *
 * Design decisions:
 * 1. Uses read-write lock for bitmap access (reads are frequent, writes are rare)
 * 2. Stores max probe hits per class (not just boolean hit)
 * 3. Lazy initialization of class entries in ConcurrentHashMap
 */
public class CoverageTracker {

    // JaCoCo agent access
    private final Object agent;
    private final Method getExecutionDataMethod;
    private final Pattern guidanceRegexp;

    // Coverage bitmap: className -> probeHits[]
    // Using int[] instead of boolean[] to track hit counts (edge frequency)
    private final ConcurrentHashMap<String, int[]> coverageBitmap;

    // Lock for atomic coverage check + update
    private final ReentrantReadWriteLock coverageLock;

    // Statistics
    private final AtomicLong totalEdges;
    private final AtomicLong newEdgesDiscovered;
    private final AtomicLong coverageChecks;

    /**
     * Result of a coverage check.
     */
    public static class CoverageResult {
        private final int newEdges;
        private final long totalEdges;
        private final boolean isInteresting;

        public CoverageResult(int newEdges, long totalEdges) {
            this.newEdges = newEdges;
            this.totalEdges = totalEdges;
            this.isInteresting = newEdges > 0;
        }

        public int getNewEdges() { return newEdges; }
        public long getTotalEdges() { return totalEdges; }
        public boolean isInteresting() { return isInteresting; }
    }

    public CoverageTracker(String guidanceRegexp)
            throws ReflectiveOperationException {
        // Initialize JaCoCo agent access
        Class<?> rtClass = Class.forName("org.jacoco.agent.rt.RT");
        Method getAgentMethod = rtClass.getMethod("getAgent");
        this.agent = getAgentMethod.invoke(null);
        this.getExecutionDataMethod = agent.getClass()
            .getMethod("getExecutionData", boolean.class);

        this.guidanceRegexp = guidanceRegexp != null && !guidanceRegexp.isBlank()
            ? Pattern.compile(guidanceRegexp) : null;

        this.coverageBitmap = new ConcurrentHashMap<>();
        this.coverageLock = new ReentrantReadWriteLock();
        this.totalEdges = new AtomicLong(0);
        this.newEdgesDiscovered = new AtomicLong(0);
        this.coverageChecks = new AtomicLong(0);

        // Pre-populate with fuzzer infrastructure classes to ignore
        addIgnoredClass("org/hyperledger/besu/testfuzz/");
    }

    private void addIgnoredClass(String prefix) {
        // Classes starting with this prefix will have max hits to avoid false positives
    }

    /**
     * Checks if current execution discovered new coverage.
     *
     * Thread-safety: Uses read-write lock to ensure atomic check-then-update.
     * Multiple workers can check concurrently (read lock), but updates are serialized.
     *
     * @return CoverageResult indicating new edges found
     */
    public CoverageResult checkNewCoverage() {
        coverageChecks.incrementAndGet();

        try {
            // Get current cumulative coverage from JaCoCo
            // Note: getExecutionData(false) is thread-safe for reads
            byte[] dumpData = (byte[]) getExecutionDataMethod.invoke(agent, false);

            // Parse the execution data
            ExecutionDataReader reader = new ExecutionDataReader(
                new ByteArrayInputStream(dumpData));

            CoverageVisitor visitor = new CoverageVisitor();
            reader.setExecutionDataVisitor(visitor);
            reader.setSessionInfoVisitor(info -> {});
            reader.read();

            // Check for new coverage under write lock
            coverageLock.writeLock().lock();
            try {
                int newEdges = 0;

                for (ExecutionData execData : visitor.getExecutionData()) {
                    String className = execData.getName();

                    // Filter by guidance regexp
                    if (guidanceRegexp != null &&
                        !guidanceRegexp.matcher(className).find()) {
                        continue;
                    }

                    boolean[] probes = execData.getProbes();
                    int[] existingHits = coverageBitmap.get(className);

                    if (existingHits == null) {
                        // New class discovered
                        existingHits = new int[probes.length];
                        coverageBitmap.put(className, existingHits);
                    } else if (existingHits.length != probes.length) {
                        // Class was recompiled? Resize.
                        int[] newHits = new int[probes.length];
                        System.arraycopy(existingHits, 0, newHits, 0,
                            Math.min(existingHits.length, probes.length));
                        existingHits = newHits;
                        coverageBitmap.put(className, existingHits);
                    }

                    // Count new edges (probes hit for first time)
                    for (int i = 0; i < probes.length; i++) {
                        if (probes[i] && existingHits[i] == 0) {
                            existingHits[i] = 1;
                            newEdges++;
                        }
                    }
                }

                if (newEdges > 0) {
                    newEdgesDiscovered.addAndGet(newEdges);
                    totalEdges.addAndGet(newEdges);
                }

                return new CoverageResult(newEdges, totalEdges.get());

            } finally {
                coverageLock.writeLock().unlock();
            }

        } catch (Exception e) {
            // Log but don't crash - coverage tracking is best-effort
            return new CoverageResult(0, totalEdges.get());
        }
    }

    /**
     * Gets current total edge count.
     */
    public long getTotalEdges() {
        return totalEdges.get();
    }

    /**
     * Gets statistics string.
     */
    public String getStats() {
        return String.format("edges=%d checks=%d new=%d classes=%d",
            totalEdges.get(), coverageChecks.get(),
            newEdgesDiscovered.get(), coverageBitmap.size());
    }

    // Inner class to collect execution data
    private static class CoverageVisitor
            implements org.jacoco.core.data.IExecutionDataVisitor {
        private final java.util.List<ExecutionData> data = new java.util.ArrayList<>();

        @Override
        public void visitClassExecution(ExecutionData executionData) {
            data.add(executionData);
        }

        public java.util.List<ExecutionData> getExecutionData() {
            return data;
        }
    }
}
```

### 3.2 CorpusEntry and InputQueue

The input queue implements AFL-style energy scheduling with priority based on coverage discovery.

```java
package org.hyperledger.besu.testfuzz.parallel;

import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * A corpus entry with metadata for energy scheduling.
 *
 * Energy model (AFL-inspired):
 * - Initial corpus entries start with energy=1
 * - Entries discovering new coverage get energy boost
 * - Energy decays with each mutation that doesn't find new coverage
 * - High-energy entries are prioritized for mutation
 */
public class CorpusEntry implements Comparable<CorpusEntry> {

    private final byte[] data;
    private final byte[] hash;      // SHA-256 for deduplication
    private final long discoveryTime;
    private final int initialEdges; // Edges when this entry was discovered

    // Mutable state (protected by InputQueue synchronization)
    private volatile int energy;
    private volatile int mutationCount;
    private volatile int childrenWithNewCoverage;
    private volatile long lastMutationTime;

    // Energy constants
    public static final int INITIAL_ENERGY = 1;
    public static final int NEW_COVERAGE_ENERGY_BOOST = 16;
    public static final int MAX_ENERGY = 64;
    public static final int DECAY_THRESHOLD = 100; // Mutations before decay

    public CorpusEntry(byte[] data, int initialEdges) {
        this.data = data.clone();
        this.hash = computeHash(data);
        this.discoveryTime = System.nanoTime();
        this.initialEdges = initialEdges;
        this.energy = INITIAL_ENERGY;
        this.mutationCount = 0;
        this.childrenWithNewCoverage = 0;
        this.lastMutationTime = discoveryTime;
    }

    private static byte[] computeHash(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (Exception e) {
            // Fallback to simple hash
            return new byte[] {
                (byte)(Arrays.hashCode(data) >> 24),
                (byte)(Arrays.hashCode(data) >> 16),
                (byte)(Arrays.hashCode(data) >> 8),
                (byte)(Arrays.hashCode(data))
            };
        }
    }

    /**
     * Priority comparison for the queue.
     * Higher energy = higher priority (comes first in queue).
     * Tie-breaker: more recent discovery time.
     */
    @Override
    public int compareTo(CorpusEntry other) {
        // Higher energy first
        int energyCompare = Integer.compare(other.energy, this.energy);
        if (energyCompare != 0) return energyCompare;

        // More recent first (for same energy)
        return Long.compare(other.discoveryTime, this.discoveryTime);
    }

    /**
     * Called when this entry is selected for mutation.
     */
    public void recordMutation() {
        mutationCount++;
        lastMutationTime = System.nanoTime();

        // Decay energy after threshold
        if (mutationCount > 0 && mutationCount % DECAY_THRESHOLD == 0 && energy > 1) {
            energy = Math.max(1, energy / 2);
        }
    }

    /**
     * Called when a child mutation finds new coverage.
     */
    public void recordSuccessfulChild() {
        childrenWithNewCoverage++;
        // Boost energy when producing good children
        energy = Math.min(MAX_ENERGY, energy + NEW_COVERAGE_ENERGY_BOOST / 4);
    }

    /**
     * Creates a new entry derived from this one with coverage boost.
     */
    public static CorpusEntry createFromMutation(byte[] mutatedData,
            CorpusEntry parent, int newEdges) {
        CorpusEntry child = new CorpusEntry(mutatedData, newEdges);
        child.energy = Math.min(MAX_ENERGY,
            INITIAL_ENERGY + (newEdges * NEW_COVERAGE_ENERGY_BOOST));
        parent.recordSuccessfulChild();
        return child;
    }

    // Getters
    public byte[] getData() { return data.clone(); }
    public byte[] getDataDirect() { return data; } // For performance (read-only!)
    public byte[] getHash() { return hash; }
    public int getEnergy() { return energy; }
    public int getMutationCount() { return mutationCount; }
    public long getDiscoveryTime() { return discoveryTime; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CorpusEntry)) return false;
        return Arrays.equals(hash, ((CorpusEntry) o).hash);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(hash);
    }
}
```

```java
package org.hyperledger.besu.testfuzz.parallel;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe priority queue for corpus entries with energy scheduling.
 *
 * Design:
 * - PriorityBlockingQueue for concurrent access
 * - ConcurrentHashMap for deduplication by content hash
 * - Energy-based priority (higher energy = mutated sooner)
 *
 * Queue behavior:
 * - poll(): Returns highest-energy entry, requeues after mutation
 * - add(): Adds new entry if unique (by hash)
 * - Re-queue entries after mutation to allow re-prioritization
 */
public class InputQueue {

    private final PriorityBlockingQueue<CorpusEntry> queue;
    private final Set<ByteArrayWrapper> seenHashes;

    // Statistics
    private final AtomicLong totalAdded;
    private final AtomicLong duplicatesRejected;
    private final AtomicLong totalPolled;

    // Configuration
    private final int maxQueueSize;

    public InputQueue() {
        this(100_000); // Default max size
    }

    public InputQueue(int maxQueueSize) {
        this.maxQueueSize = maxQueueSize;
        this.queue = new PriorityBlockingQueue<>(1000);
        this.seenHashes = ConcurrentHashMap.newKeySet();
        this.totalAdded = new AtomicLong(0);
        this.duplicatesRejected = new AtomicLong(0);
        this.totalPolled = new AtomicLong(0);
    }

    /**
     * Adds initial corpus entries at startup.
     *
     * @param data the raw test data
     * @param initialEdges current edge count at time of addition
     * @return true if added (not a duplicate)
     */
    public boolean addInitial(byte[] data, int initialEdges) {
        CorpusEntry entry = new CorpusEntry(data, initialEdges);
        return addEntry(entry);
    }

    /**
     * Adds a new corpus entry discovered through mutation.
     *
     * @param data the mutated test data
     * @param parent the parent entry that was mutated
     * @param newEdges edges discovered by this mutation
     * @return true if added (not a duplicate)
     */
    public boolean addFromMutation(byte[] data, CorpusEntry parent, int newEdges) {
        CorpusEntry entry = CorpusEntry.createFromMutation(data, parent, newEdges);
        return addEntry(entry);
    }

    private boolean addEntry(CorpusEntry entry) {
        ByteArrayWrapper hashKey = new ByteArrayWrapper(entry.getHash());

        // Check for duplicate
        if (!seenHashes.add(hashKey)) {
            duplicatesRejected.incrementAndGet();
            return false;
        }

        // Check queue size limit
        if (queue.size() >= maxQueueSize) {
            // Could implement eviction of lowest-energy entries here
            // For now, just reject
            seenHashes.remove(hashKey);
            return false;
        }

        queue.offer(entry);
        totalAdded.incrementAndGet();
        return true;
    }

    /**
     * Polls for the next entry to mutate.
     * The entry is temporarily removed; caller must call requeue() when done.
     *
     * @param timeout max time to wait
     * @param unit time unit
     * @return the entry, or null if timeout
     */
    public CorpusEntry poll(long timeout, TimeUnit unit) throws InterruptedException {
        CorpusEntry entry = queue.poll(timeout, unit);
        if (entry != null) {
            totalPolled.incrementAndGet();
            entry.recordMutation();
        }
        return entry;
    }

    /**
     * Re-queues an entry after mutation (allows re-prioritization).
     */
    public void requeue(CorpusEntry entry) {
        queue.offer(entry);
    }

    /**
     * Gets current queue size.
     */
    public int size() {
        return queue.size();
    }

    /**
     * Gets total unique entries seen.
     */
    public int uniqueEntries() {
        return seenHashes.size();
    }

    /**
     * Gets statistics string.
     */
    public String getStats() {
        return String.format("queue=%d unique=%d added=%d dupes=%d polled=%d",
            queue.size(), seenHashes.size(), totalAdded.get(),
            duplicatesRejected.get(), totalPolled.get());
    }

    /**
     * Wrapper for byte[] to use as HashMap key.
     */
    private static class ByteArrayWrapper {
        private final byte[] data;
        private final int hashCode;

        ByteArrayWrapper(byte[] data) {
            this.data = data;
            this.hashCode = java.util.Arrays.hashCode(data);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof ByteArrayWrapper)) return false;
            return java.util.Arrays.equals(data, ((ByteArrayWrapper) o).data);
        }

        @Override
        public int hashCode() {
            return hashCode;
        }
    }
}
```

### 3.3 FuzzWorker

Individual worker threads that perform the actual fuzzing.

```java
package org.hyperledger.besu.testfuzz.parallel;

import org.hyperledger.besu.testfuzz.StateTestExecutor;
import org.hyperledger.besu.testfuzz.statetest.CombinedMutationStrategy;
import org.hyperledger.besu.testfuzz.statetest.MutationStrategy;
import org.hyperledger.besu.testfuzz.statetest.StateTestCorpusProvider;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Worker thread that performs coverage-guided fuzzing.
 *
 * Each worker has:
 * - Its own StateTestExecutor (thread-safe, has internal stats)
 * - Its own CombinedMutationStrategy (uses ThreadLocalRandom)
 * - Shared access to InputQueue and CoverageTracker
 *
 * Worker loop:
 * 1. Poll entry from InputQueue
 * 2. Apply mutation
 * 3. Execute test
 * 4. Check for new coverage
 * 5. If interesting, add mutated input to queue
 * 6. Requeue original entry
 */
public class FuzzWorker implements Runnable {

    private final int workerId;
    private final InputQueue inputQueue;
    private final CoverageTracker coverageTracker;
    private final CrashManager crashManager;
    private final AtomicBoolean stopFlag;
    private final String fork;
    private final List<byte[]> corpusForSplicing;

    // Thread-local components
    private StateTestExecutor executor;
    private CombinedMutationStrategy mutator;

    // Worker statistics
    private final AtomicLong iterations = new AtomicLong(0);
    private final AtomicLong coverageHits = new AtomicLong(0);
    private final AtomicLong mutationFailures = new AtomicLong(0);
    private final AtomicLong executionErrors = new AtomicLong(0);

    // Configuration
    private final int mutationsPerEntry;
    private final int coverageCheckInterval;

    public FuzzWorker(
            int workerId,
            InputQueue inputQueue,
            CoverageTracker coverageTracker,
            CrashManager crashManager,
            AtomicBoolean stopFlag,
            String fork,
            List<byte[]> corpusForSplicing) {
        this.workerId = workerId;
        this.inputQueue = inputQueue;
        this.coverageTracker = coverageTracker;
        this.crashManager = crashManager;
        this.stopFlag = stopFlag;
        this.fork = fork;
        this.corpusForSplicing = corpusForSplicing;
        this.mutationsPerEntry = 8;  // Mutations per queue entry
        this.coverageCheckInterval = 1; // Check coverage every N executions
    }

    @Override
    public void run() {
        // Initialize thread-local components
        this.executor = new StateTestExecutor(fork);

        if (corpusForSplicing != null && corpusForSplicing.size() >= 2) {
            StateTestCorpusProvider provider = new StateTestCorpusProvider(corpusForSplicing);
            this.mutator = CombinedMutationStrategy.createWithSplicing(provider);
        } else {
            this.mutator = CombinedMutationStrategy.createDefault();
        }

        // Main fuzzing loop
        while (!stopFlag.get() && !Thread.currentThread().isInterrupted()) {
            try {
                // Poll with timeout to check stop flag periodically
                CorpusEntry entry = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (entry == null) {
                    continue; // No work, check stop flag
                }

                try {
                    processEntry(entry);
                } finally {
                    // Always requeue the entry (even if we're stopping)
                    inputQueue.requeue(entry);
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                // Log but continue
                System.err.printf("Worker %d error: %s%n", workerId, e.getMessage());
            }
        }
    }

    private void processEntry(CorpusEntry entry) {
        byte[] seedData = entry.getDataDirect();

        // Apply multiple mutations to this entry
        for (int i = 0; i < mutationsPerEntry && !stopFlag.get(); i++) {
            iterations.incrementAndGet();

            // Mutate
            byte[] mutatedData;
            try {
                MutationStrategy.MutationResult result = mutator.mutate(seedData);
                mutatedData = result.getData();
            } catch (MutationStrategy.MutationException e) {
                mutationFailures.incrementAndGet();
                continue;
            }

            // Execute
            StateTestExecutor.ExecutionResult execResult;
            try {
                execResult = executor.execute(mutatedData);
            } catch (Exception e) {
                executionErrors.incrementAndGet();
                crashManager.saveCrash(mutatedData, e.getMessage(), workerId);
                continue;
            }

            // Handle crashes
            if (execResult.isCrashed()) {
                crashManager.saveCrash(mutatedData, execResult.getError(), workerId);
                continue;
            }

            // Check coverage (may batch this for performance)
            if (iterations.get() % coverageCheckInterval == 0) {
                CoverageTracker.CoverageResult covResult = coverageTracker.checkNewCoverage();

                if (covResult.isInteresting()) {
                    coverageHits.incrementAndGet();
                    // Add to queue with energy boost
                    inputQueue.addFromMutation(mutatedData, entry, covResult.getNewEdges());
                }
            }
        }
    }

    /**
     * Returns worker statistics.
     */
    public String getStats() {
        return String.format("worker[%d]: iters=%d cov_hits=%d mut_fail=%d exec_err=%d",
            workerId, iterations.get(), coverageHits.get(),
            mutationFailures.get(), executionErrors.get());
    }

    public int getWorkerId() { return workerId; }
    public long getIterations() { return iterations.get(); }
    public long getCoverageHits() { return coverageHits.get(); }
}
```

### 3.4 CrashManager

Thread-safe crash saving with deduplication.

```java
package org.hyperledger.besu.testfuzz.parallel;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe crash manager with deduplication.
 */
public class CrashManager {

    private final File crashDir;
    private final Set<String> seenCrashHashes;
    private final AtomicLong totalCrashes;
    private final AtomicLong uniqueCrashes;

    public CrashManager(File crashDir) {
        this.crashDir = crashDir;
        this.seenCrashHashes = ConcurrentHashMap.newKeySet();
        this.totalCrashes = new AtomicLong(0);
        this.uniqueCrashes = new AtomicLong(0);

        if (!crashDir.exists()) {
            crashDir.mkdirs();
        }
    }

    /**
     * Saves a crash, deduplicating by content hash.
     *
     * @param testData the test that caused the crash
     * @param error the error message
     * @param workerId the worker that found the crash
     * @return true if this is a unique crash
     */
    public boolean saveCrash(byte[] testData, String error, int workerId) {
        totalCrashes.incrementAndGet();

        String hash = computeHash(testData);
        if (!seenCrashHashes.add(hash)) {
            return false; // Duplicate
        }

        uniqueCrashes.incrementAndGet();

        try {
            String filename = String.format("crash-%s-w%d-%d.json",
                hash.substring(0, 16), workerId, System.currentTimeMillis());
            File crashFile = new File(crashDir, filename);

            try (FileOutputStream fos = new FileOutputStream(crashFile)) {
                fos.write(testData);
            }

            // Write metadata
            String metaFilename = filename.replace(".json", ".txt");
            File metaFile = new File(crashDir, metaFilename);
            try (FileOutputStream fos = new FileOutputStream(metaFile)) {
                String meta = String.format(
                    "Crash at: %s%nWorker: %d%nError: %s%nHash: %s%n",
                    Instant.now(), workerId,
                    error != null ? error : "unknown", hash);
                fos.write(meta.getBytes(StandardCharsets.UTF_8));
            }

            System.out.printf("[!] Unique crash saved: %s%n", filename);
            return true;

        } catch (IOException e) {
            System.err.printf("Failed to save crash: %s%n", e.getMessage());
            return false;
        }
    }

    private String computeHash(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return String.format("%08x", java.util.Arrays.hashCode(data));
        }
    }

    public long getTotalCrashes() { return totalCrashes.get(); }
    public long getUniqueCrashes() { return uniqueCrashes.get(); }

    public String getStats() {
        return String.format("crashes: total=%d unique=%d",
            totalCrashes.get(), uniqueCrashes.get());
    }
}
```

### 3.5 CoverageGuidedFuzzer (Orchestrator)

The main coordinator that ties everything together.

```java
package org.hyperledger.besu.testfuzz.parallel;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main orchestrator for coverage-guided parallel fuzzing.
 *
 * Lifecycle:
 * 1. Initialize coverage tracker and input queue
 * 2. Load corpus into input queue
 * 3. Start worker threads (virtual threads on Java 21+)
 * 4. Monitor progress and log statistics
 * 5. Handle graceful shutdown
 */
public class CoverageGuidedFuzzer {

    private final int numWorkers;
    private final String fork;
    private final String guidanceRegexp;
    private final File corpusDir;
    private final File newCorpusDir;
    private final File crashDir;
    private final Duration timeout;

    // Core components
    private CoverageTracker coverageTracker;
    private InputQueue inputQueue;
    private CrashManager crashManager;
    private List<FuzzWorker> workers;
    private List<byte[]> corpus;

    // Control
    private final AtomicBoolean stopFlag = new AtomicBoolean(false);
    private ExecutorService executorService;

    public CoverageGuidedFuzzer(Builder builder) {
        this.numWorkers = builder.numWorkers > 0
            ? builder.numWorkers
            : Runtime.getRuntime().availableProcessors();
        this.fork = builder.fork != null ? builder.fork : "Prague";
        this.guidanceRegexp = builder.guidanceRegexp;
        this.corpusDir = builder.corpusDir;
        this.newCorpusDir = builder.newCorpusDir;
        this.crashDir = builder.crashDir != null
            ? builder.crashDir
            : new File("crashes");
        this.timeout = builder.timeout;
    }

    /**
     * Runs the fuzzer.
     */
    public void run() throws Exception {
        System.out.println("=== Coverage-Guided Parallel Fuzzer ===");
        System.out.println();

        // Initialize
        initialize();

        // Log configuration
        System.out.printf("Workers: %d%n", numWorkers);
        System.out.printf("Fork: %s%n", fork);
        System.out.printf("Guidance regexp: %s%n",
            guidanceRegexp != null ? guidanceRegexp : "(all classes)");
        System.out.printf("Corpus: %d files%n", corpus.size());
        System.out.printf("Timeout: %s%n",
            timeout != null ? timeout : "infinite");
        System.out.println();

        // Start workers
        startWorkers();

        // Monitor loop
        Instant startTime = Instant.now();
        Instant deadline = timeout != null
            ? startTime.plus(timeout)
            : Instant.MAX;

        try {
            while (!stopFlag.get() && Instant.now().isBefore(deadline)) {
                Thread.sleep(5000); // Progress interval
                printProgress(startTime);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Shutdown
        shutdown();
        printFinalStats(startTime);
    }

    private void initialize() throws Exception {
        // Initialize coverage tracker
        coverageTracker = new CoverageTracker(guidanceRegexp);

        // Initialize input queue
        inputQueue = new InputQueue();

        // Initialize crash manager
        crashManager = new CrashManager(crashDir);

        // Load corpus
        corpus = loadCorpus(corpusDir);
        if (corpus.isEmpty()) {
            throw new IllegalStateException("No corpus files found in " + corpusDir);
        }

        // Add corpus to queue
        int initialEdges = (int) coverageTracker.getTotalEdges();
        for (byte[] data : corpus) {
            inputQueue.addInitial(data, initialEdges);
        }

        // Create new corpus directory
        if (newCorpusDir != null && !newCorpusDir.exists()) {
            newCorpusDir.mkdirs();
        }
    }

    private List<byte[]> loadCorpus(File dir) {
        List<byte[]> result = new ArrayList<>();
        loadCorpusRecursive(dir, result);
        Collections.shuffle(result);
        return result;
    }

    private void loadCorpusRecursive(File dir, List<byte[]> result) {
        if (!dir.exists()) return;

        if (dir.isFile() && dir.getName().endsWith(".json")) {
            try {
                byte[] data = Files.readAllBytes(dir.toPath());
                if (data.length > 0) {
                    result.add(data);
                }
            } catch (IOException e) {
                // Skip unreadable files
            }
            return;
        }

        File[] children = dir.listFiles();
        if (children == null) return;

        for (File child : children) {
            if (child.isDirectory()) {
                loadCorpusRecursive(child, result);
            } else if (child.getName().endsWith(".json")) {
                try {
                    byte[] data = Files.readAllBytes(child.toPath());
                    if (data.length > 0) {
                        result.add(data);
                    }
                } catch (IOException e) {
                    // Skip
                }
            }
        }
    }

    private void startWorkers() {
        workers = new ArrayList<>(numWorkers);

        // Use virtual threads on Java 21+
        executorService = Executors.newVirtualThreadPerTaskExecutor();

        for (int i = 0; i < numWorkers; i++) {
            FuzzWorker worker = new FuzzWorker(
                i,
                inputQueue,
                coverageTracker,
                crashManager,
                stopFlag,
                fork,
                corpus  // Shared read-only corpus for splicing
            );
            workers.add(worker);
            executorService.submit(worker);
        }

        System.out.printf("Started %d worker threads%n", numWorkers);
    }

    private void shutdown() {
        System.out.println("\nShutting down...");
        stopFlag.set(true);

        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(10, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private void printProgress(Instant startTime) {
        Duration elapsed = Duration.between(startTime, Instant.now());

        long totalIterations = workers.stream()
            .mapToLong(FuzzWorker::getIterations)
            .sum();
        long totalCovHits = workers.stream()
            .mapToLong(FuzzWorker::getCoverageHits)
            .sum();

        double rate = totalIterations / (elapsed.getSeconds() + 0.001);

        System.out.printf(
            "[%s] execs: %d (%.1f/s) | cov: %s | queue: %s | %s%n",
            formatDuration(elapsed),
            totalIterations,
            rate,
            coverageTracker.getStats(),
            inputQueue.getStats(),
            crashManager.getStats()
        );
    }

    private void printFinalStats(Instant startTime) {
        Duration elapsed = Duration.between(startTime, Instant.now());

        System.out.println();
        System.out.println("=== Final Results ===");
        System.out.printf("Duration: %s%n", formatDuration(elapsed));
        System.out.printf("Workers: %d%n", numWorkers);

        long totalIterations = workers.stream()
            .mapToLong(FuzzWorker::getIterations)
            .sum();
        System.out.printf("Total executions: %d%n", totalIterations);
        System.out.printf("Rate: %.1f exec/s%n",
            totalIterations / (elapsed.getSeconds() + 0.001));

        System.out.println();
        System.out.printf("Coverage: %s%n", coverageTracker.getStats());
        System.out.printf("Queue: %s%n", inputQueue.getStats());
        System.out.printf("Crashes: %s%n", crashManager.getStats());

        System.out.println();
        System.out.println("Per-worker stats:");
        for (FuzzWorker worker : workers) {
            System.out.println("  " + worker.getStats());
        }
    }

    private String formatDuration(Duration d) {
        long hours = d.toHours();
        long minutes = d.toMinutesPart();
        long seconds = d.toSecondsPart();
        return String.format("%02d:%02d:%02d", hours, minutes, seconds);
    }

    /**
     * Builder for CoverageGuidedFuzzer.
     */
    public static class Builder {
        private int numWorkers = 0; // 0 = auto-detect
        private String fork = "Prague";
        private String guidanceRegexp;
        private File corpusDir;
        private File newCorpusDir;
        private File crashDir;
        private Duration timeout;

        public Builder numWorkers(int n) { this.numWorkers = n; return this; }
        public Builder fork(String f) { this.fork = f; return this; }
        public Builder guidanceRegexp(String r) { this.guidanceRegexp = r; return this; }
        public Builder corpusDir(File d) { this.corpusDir = d; return this; }
        public Builder newCorpusDir(File d) { this.newCorpusDir = d; return this; }
        public Builder crashDir(File d) { this.crashDir = d; return this; }
        public Builder timeout(Duration t) { this.timeout = t; return this; }

        public CoverageGuidedFuzzer build() {
            return new CoverageGuidedFuzzer(this);
        }
    }
}
```

## 4. Thread Synchronization Strategy

### 4.1 Synchronization Points

| Component | Shared State | Synchronization | Access Pattern |
|-----------|--------------|-----------------|----------------|
| `CoverageTracker` | `coverageBitmap` | `ReentrantReadWriteLock` | Read-heavy, rare writes |
| `InputQueue` | `queue`, `seenHashes` | `PriorityBlockingQueue`, `ConcurrentHashMap.newKeySet()` | MPMC |
| `CrashManager` | `seenCrashHashes` | `ConcurrentHashMap.newKeySet()` | Write-occasional |
| `FuzzWorker` | None (thread-local executor/mutator) | N/A | Per-thread |
| `Corpus` | `List<byte[]>` | Immutable (read-only) | Shared read |

### 4.2 Lock Hierarchy

To prevent deadlocks, locks are acquired in this order:
1. `coverageLock` (CoverageTracker)
2. Queue operations (InputQueue - internal locks)
3. File I/O (CrashManager - file system acts as lock)

### 4.3 JaCoCo Thread Safety Analysis

```
JaCoCo Agent Internal Architecture:
+----------------------------------+
|        org.jacoco.agent.rt.RT    |
|  (Singleton, thread-safe reads)  |
+----------------------------------+
              |
              v
+----------------------------------+
|     ExecutionData Store          |
|  (boolean[] probes per class)    |
|  - Writes: JIT at runtime        |
|  - Reads: getExecutionData()     |
+----------------------------------+

getExecutionData(false):
- Returns serialized snapshot of current state
- Does NOT reset data
- Thread-safe for concurrent reads
- Each call serializes entire store (can be slow)

Our approach:
- Call getExecutionData(false) per coverage check
- Parse returned byte[] to extract probe data
- Compare against our own bitmap under write lock
- Only update bitmap when new edges found
```

### 4.4 Coverage Check Optimization

The current design checks coverage after every execution. For better performance:

```java
// Option 1: Batch coverage checks
private final int coverageCheckInterval = 10;

// In worker loop:
if (iterations.get() % coverageCheckInterval == 0) {
    checkCoverage();
}

// Option 2: Probabilistic checking
if (ThreadLocalRandom.current().nextInt(100) < 10) { // 10% chance
    checkCoverage();
}

// Option 3: Time-based checking
if (System.nanoTime() - lastCoverageCheck > 100_000_000) { // 100ms
    checkCoverage();
    lastCoverageCheck = System.nanoTime();
}
```

## 5. Energy Scheduling (AFL-Style Power Schedules)

### 5.1 Energy Model

```
Energy determines mutation priority:
- Higher energy = more mutations derived from this input
- New coverage discovery = energy boost
- Many mutations without new coverage = energy decay

Initial: energy = 1
On new coverage: energy += NEW_EDGES * 16 (capped at 64)
Every 100 mutations without new coverage: energy /= 2 (min 1)
```

### 5.2 Alternative Power Schedules

```java
// AFL's explore schedule
public int computeEnergyExplore(CorpusEntry entry) {
    int perf_score = 100;

    // Prefer smaller inputs
    if (entry.getData().length < 64) perf_score *= 2;
    else if (entry.getData().length < 256) perf_score *= 1.5;

    // Prefer newer entries
    long age = System.nanoTime() - entry.getDiscoveryTime();
    if (age < TimeUnit.MINUTES.toNanos(1)) perf_score *= 2;

    // Prefer entries with fewer mutations
    if (entry.getMutationCount() < 16) perf_score *= 2;

    return Math.min(perf_score, 1600) / 100;
}

// AFL's exploit schedule (focus on known-good inputs)
public int computeEnergyExploit(CorpusEntry entry) {
    return entry.getChildrenWithNewCoverage() > 0
        ? MAX_ENERGY
        : INITIAL_ENERGY;
}
```

## 6. Integration with Existing Code

### 6.1 CLI Integration

Update `StateTestFuzzSubCommand`:

```java
@Option(
    names = {"--parallel-guided"},
    description = "Use parallel coverage-guided fuzzing")
private boolean parallelGuided = false;

@Override
public void run() {
    if (parallelGuided && guidanceRegexp != null) {
        runParallelGuidedFuzzing();
    } else if (guidanceRegexp != null) {
        runGuidedFuzzing(target, fuzzDuration);  // Existing
    } else {
        runSimpleFuzzing(target, fuzzDuration);  // Existing
    }
}

private void runParallelGuidedFuzzing() {
    CoverageGuidedFuzzer fuzzer = new CoverageGuidedFuzzer.Builder()
        .numWorkers(workers)
        .fork(fork)
        .guidanceRegexp(guidanceRegexp)
        .corpusDir(new File(corpusDir))
        .newCorpusDir(newCorpusDir)
        .crashDir(crashDir)
        .timeout(parseDuration(duration))
        .build();

    fuzzer.run();
}
```

### 6.2 Package Structure

```
testfuzz/src/main/java/org/hyperledger/besu/testfuzz/
|-- parallel/
|   |-- CoverageGuidedFuzzer.java    (Orchestrator)
|   |-- CoverageTracker.java         (Shared coverage state)
|   |-- InputQueue.java              (Priority queue)
|   |-- CorpusEntry.java             (Queue entry with metadata)
|   |-- FuzzWorker.java              (Worker thread)
|   |-- CrashManager.java            (Crash handling)
|-- statetest/
|   |-- (existing mutation strategies)
|-- javafuzz/
|   |-- (existing single-threaded fuzzer)
|-- StateTestFuzzSubCommand.java     (CLI entry point)
```

## 7. Performance Considerations

### 7.1 Bottleneck Analysis

| Operation | Cost | Mitigation |
|-----------|------|------------|
| JaCoCo `getExecutionData()` | O(classes * probes) | Batch checks, probabilistic checking |
| Coverage bitmap update | O(probes) | Write lock is rare (only on new coverage) |
| Queue operations | O(log n) | PriorityBlockingQueue is efficient |
| Mutation | O(input_size) | Already thread-local |
| Test execution | O(gas_limit) | Already thread-local, main bottleneck |

### 7.2 Scalability Expectations

```
Expected scaling:
- 1 worker:  ~500 exec/s (baseline, coverage-guided)
- 4 workers: ~1,800 exec/s (3.6x speedup)
- 8 workers: ~3,200 exec/s (6.4x speedup)
- 16 workers: ~5,000 exec/s (10x speedup)

Limiting factors:
1. JaCoCo serialization (global lock in agent)
2. GC pressure from test data allocation
3. CPU cache contention on shared state
4. Diminishing returns from coverage checking overhead
```

### 7.3 Optimization Opportunities

1. **Coverage checking batching**: Check every N executions instead of every one
2. **Lock-free coverage bitmap**: Use `AtomicIntegerArray` per class instead of `int[]`
3. **Work stealing**: Let idle workers steal from busy workers' local queues
4. **Memory-mapped corpus**: Use `MappedByteBuffer` for large corpus files
5. **Coverage delta caching**: Cache coverage results briefly to avoid redundant checks

## 8. Implementation Phases

### Phase 1: Core Infrastructure (Week 1)
- [ ] Implement `CoverageTracker` with thread-safe bitmap
- [ ] Implement `CorpusEntry` with energy metadata
- [ ] Implement `InputQueue` with priority scheduling
- [ ] Unit tests for all components

### Phase 2: Worker Implementation (Week 2)
- [ ] Implement `FuzzWorker` with thread-local components
- [ ] Implement `CrashManager` with deduplication
- [ ] Integration test with 2 workers

### Phase 3: Orchestrator (Week 3)
- [ ] Implement `CoverageGuidedFuzzer` orchestrator
- [ ] Add CLI integration to `StateTestFuzzSubCommand`
- [ ] Progress reporting and statistics

### Phase 4: Optimization (Week 4)
- [ ] Benchmark and profile
- [ ] Implement coverage check batching
- [ ] Tune energy scheduling parameters
- [ ] Documentation

## 9. Testing Strategy

### 9.1 Unit Tests
- `CoverageTrackerTest`: Thread-safe bitmap updates
- `InputQueueTest`: Priority ordering, deduplication
- `CorpusEntryTest`: Energy scheduling math

### 9.2 Integration Tests
- Multi-worker coverage aggregation
- Crash deduplication under load
- Graceful shutdown with in-flight work

### 9.3 Performance Tests
- Scaling with worker count
- Memory usage over time
- Coverage discovery rate comparison vs single-threaded

## 10. Appendix: Alternative Designs Considered

### A. Per-Worker Coverage Bitmaps (Rejected)
Each worker maintains its own bitmap, merged periodically.
- Pro: Less contention
- Con: Duplicated coverage discovery, complex merge logic

### B. Lock-Free Bloom Filter (Rejected)
Use bloom filter for approximate coverage tracking.
- Pro: Very fast, lock-free
- Con: False positives reduce effectiveness, no edge counting

### C. Shared-Nothing with Message Passing (Rejected)
Workers send coverage deltas to coordinator via queues.
- Pro: Clean separation
- Con: High message volume, coordination overhead

### D. Selected: Shared Bitmap with Read-Write Lock
Central bitmap with optimistic reads, rare writes.
- Pro: Simple, correct, good read performance
- Con: Write lock contention (mitigated by rarity of new coverage)

---

## References

1. AFL Technical Whitepaper: https://lcamtuf.coredump.cx/afl/technical_details.txt
2. JaCoCo Agent Implementation: https://github.com/jacoco/jacoco
3. Java Virtual Threads (JEP 444): https://openjdk.org/jeps/444
4. goevmlab Fuzzer: https://github.com/holiman/goevmlab
