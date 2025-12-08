/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.testfuzz.parallel;

import org.hyperledger.besu.testfuzz.crossvm.ConsensusDivergenceManager;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Main orchestrator for coverage-guided parallel fuzzing.
 *
 * <p>Lifecycle:
 *
 * <ol>
 *   <li>Initialize coverage tracker and input queue
 *   <li>Load corpus into input queue
 *   <li>Start worker threads (virtual threads on Java 21+)
 *   <li>Monitor progress and log statistics
 *   <li>Handle graceful shutdown
 * </ol>
 */
public class CoverageGuidedFuzzer {

  private static final Logger LOG = LoggerFactory.getLogger(CoverageGuidedFuzzer.class);

  private static final int PROGRESS_INTERVAL_MS = 5000;
  private static final int SHUTDOWN_TIMEOUT_SECONDS = 10;

  private final int numWorkers;
  private final String fork;
  private final String guidanceRegexp;
  private final File corpusDir;
  private final File newCorpusDir;
  private final File crashDir;
  private final Duration timeout;
  private final boolean enableCrossVMVerification;
  private final String besuVersion;

  // Core components
  private CoverageTracker coverageTracker;
  private InputQueue inputQueue;
  private CrashManager crashManager;
  private ConsensusDivergenceManager divergenceManager; // May be null if not enabled
  private List<FuzzWorker> workers;
  private List<byte[]> corpus;

  // Control
  private final AtomicBoolean stopFlag = new AtomicBoolean(false);
  private ExecutorService executorService;

  // Statistics
  private final AtomicLong newCorpusSaved = new AtomicLong(0);

  private CoverageGuidedFuzzer(final Builder builder) {
    this.numWorkers =
        builder.numWorkers > 0 ? builder.numWorkers : Runtime.getRuntime().availableProcessors();
    this.fork = builder.fork != null ? builder.fork : "Prague";
    this.guidanceRegexp = builder.guidanceRegexp;
    this.corpusDir = builder.corpusDir;
    this.newCorpusDir = builder.newCorpusDir;
    this.crashDir = builder.crashDir != null ? builder.crashDir : new File("crashes");
    this.timeout = builder.timeout;
    this.enableCrossVMVerification = builder.enableCrossVMVerification;
    this.besuVersion = builder.besuVersion != null ? builder.besuVersion : getDefaultBesuVersion();
  }

  private static String getDefaultBesuVersion() {
    Package pkg = CoverageGuidedFuzzer.class.getPackage();
    if (pkg != null && pkg.getImplementationVersion() != null) {
      return pkg.getImplementationVersion();
    }
    return "dev";
  }

  /**
   * Runs the fuzzer.
   *
   * @throws Exception if initialization fails
   */
  public void run() throws Exception {
    System.out.println("=== Coverage-Guided Parallel Fuzzer ===");
    System.out.println();

    // Initialize
    initialize();

    // Log configuration
    System.out.printf("Workers: %d%n", numWorkers);
    System.out.printf("Fork: %s%n", fork);
    System.out.printf(
        "Guidance regexp: %s%n", guidanceRegexp != null ? guidanceRegexp : "(all classes)");
    System.out.printf("Corpus: %d files%n", corpus.size());
    System.out.printf("Timeout: %s%n", timeout != null ? timeout : "infinite");
    System.out.printf(
        "Cross-VM verification: %s%n", enableCrossVMVerification ? "enabled" : "disabled");
    System.out.println();

    // Start workers
    startWorkers();

    // Monitor loop
    Instant startTime = Instant.now();
    Instant deadline = timeout != null ? startTime.plus(timeout) : Instant.MAX;

    try {
      while (!stopFlag.get() && Instant.now().isBefore(deadline)) {
        Thread.sleep(PROGRESS_INTERVAL_MS);
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

    // Initialize cross-VM divergence manager if enabled
    if (enableCrossVMVerification) {
      divergenceManager = new ConsensusDivergenceManager(crashDir, besuVersion);
    }

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

  private List<byte[]> loadCorpus(final File dir) {
    List<byte[]> result = new ArrayList<>();
    loadCorpusRecursive(dir, result);
    Collections.shuffle(result);
    return result;
  }

  private void loadCorpusRecursive(final File dir, final List<byte[]> result) {
    if (!dir.exists()) {
      return;
    }

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
    if (children == null) {
      return;
    }

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
      FuzzWorker worker =
          new FuzzWorker(
              i,
              inputQueue,
              coverageTracker,
              crashManager,
              divergenceManager, // May be null if cross-VM verification is disabled
              stopFlag,
              fork,
              corpus // Shared read-only corpus for splicing
              );
      workers.add(worker);
      executorService.submit(worker);
    }

    System.out.printf("Started %d worker threads%n", numWorkers);
  }

  private void shutdown() {
    System.out.println();
    System.out.println("Shutting down...");
    stopFlag.set(true);

    executorService.shutdown();
    try {
      if (!executorService.awaitTermination(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
        executorService.shutdownNow();
      }
    } catch (InterruptedException e) {
      executorService.shutdownNow();
      Thread.currentThread().interrupt();
    }
  }

  private void printProgress(final Instant startTime) {
    Duration elapsed = Duration.between(startTime, Instant.now());

    long totalIterations = workers.stream().mapToLong(FuzzWorker::getIterations).sum();
    long totalCovHits = workers.stream().mapToLong(FuzzWorker::getCoverageHits).sum();

    double rate = totalIterations / (elapsed.getSeconds() + 0.001);

    System.out.printf(
        "[%s] execs: %d (%.1f/s) | cov_hits: %d | cov: %s | queue: %s | %s%n",
        formatDuration(elapsed),
        totalIterations,
        rate,
        totalCovHits,
        coverageTracker.getStats(),
        inputQueue.getStats(),
        crashManager.getStats());

    // Save new corpus entries if configured
    if (newCorpusDir != null) {
      saveNewCorpusEntries();
    }
  }

  private void saveNewCorpusEntries() {
    // This is a simplified implementation - in production you'd want
    // to track which entries have been saved already
    long uniqueEntries = inputQueue.uniqueEntries();
    if (uniqueEntries > corpus.size() + newCorpusSaved.get()) {
      // New entries have been added to the queue
      // For now, just log - full implementation would save them to disk
      LOG.debug("Queue has {} unique entries (started with {})", uniqueEntries, corpus.size());
    }
  }

  private void printFinalStats(final Instant startTime) {
    Duration elapsed = Duration.between(startTime, Instant.now());

    System.out.println();
    System.out.println("=== Final Results ===");
    System.out.printf("Duration: %s%n", formatDuration(elapsed));
    System.out.printf("Workers: %d%n", numWorkers);

    long totalIterations = workers.stream().mapToLong(FuzzWorker::getIterations).sum();
    System.out.printf("Total executions: %d%n", totalIterations);
    System.out.printf("Rate: %.1f exec/s%n", totalIterations / (elapsed.getSeconds() + 0.001));

    System.out.println();
    System.out.printf("Coverage: %s%n", coverageTracker.getStats());
    System.out.printf("Queue: %s%n", inputQueue.getStats());
    System.out.printf("Crashes: %s%n", crashManager.getStats());

    System.out.println();
    System.out.println("Per-worker stats:");
    for (FuzzWorker worker : workers) {
      System.out.printf("  %s%n", worker.getStats());
    }

    // Print cross-VM verification summary if enabled
    if (divergenceManager != null) {
      divergenceManager.printFinalSummary();
    }
  }

  private String formatDuration(final Duration d) {
    long hours = d.toHours();
    long minutes = d.toMinutesPart();
    long seconds = d.toSecondsPart();
    return String.format("%02d:%02d:%02d", hours, minutes, seconds);
  }

  /** Builder for CoverageGuidedFuzzer. */
  public static class Builder {
    private int numWorkers = 0; // 0 = auto-detect
    private String fork = "Prague";
    private String guidanceRegexp;
    private File corpusDir;
    private File newCorpusDir;
    private File crashDir;
    private Duration timeout;
    private boolean enableCrossVMVerification = false;
    private String besuVersion;

    /**
     * Sets the number of worker threads.
     *
     * @param n number of workers (0 for auto-detect)
     * @return this builder
     */
    public Builder numWorkers(final int n) {
      this.numWorkers = n;
      return this;
    }

    /**
     * Sets the EVM fork.
     *
     * @param f the fork name
     * @return this builder
     */
    public Builder fork(final String f) {
      this.fork = f;
      return this;
    }

    /**
     * Sets the guidance regexp for coverage filtering.
     *
     * @param r the regexp pattern
     * @return this builder
     */
    public Builder guidanceRegexp(final String r) {
      this.guidanceRegexp = r;
      return this;
    }

    /**
     * Sets the corpus directory.
     *
     * @param d the corpus directory
     * @return this builder
     */
    public Builder corpusDir(final File d) {
      this.corpusDir = d;
      return this;
    }

    /**
     * Sets the new corpus directory.
     *
     * @param d the new corpus directory
     * @return this builder
     */
    public Builder newCorpusDir(final File d) {
      this.newCorpusDir = d;
      return this;
    }

    /**
     * Sets the crash directory.
     *
     * @param d the crash directory
     * @return this builder
     */
    public Builder crashDir(final File d) {
      this.crashDir = d;
      return this;
    }

    /**
     * Sets the timeout duration.
     *
     * @param t the timeout
     * @return this builder
     */
    public Builder timeout(final Duration t) {
      this.timeout = t;
      return this;
    }

    /**
     * Enables or disables cross-VM consensus verification.
     *
     * <p>When enabled, corpus entries containing _crossvm metadata from other clients (e.g., geth)
     * will be executed and their trace hashes compared against the expected values to detect
     * consensus divergences.
     *
     * @param enable true to enable cross-VM verification
     * @return this builder
     */
    public Builder enableCrossVMVerification(final boolean enable) {
      this.enableCrossVMVerification = enable;
      return this;
    }

    /**
     * Sets the Besu version string for cross-VM reports.
     *
     * @param version the Besu version (e.g., "24.12.0")
     * @return this builder
     */
    public Builder besuVersion(final String version) {
      this.besuVersion = version;
      return this;
    }

    /**
     * Builds the CoverageGuidedFuzzer.
     *
     * @return a new CoverageGuidedFuzzer instance
     */
    public CoverageGuidedFuzzer build() {
      return new CoverageGuidedFuzzer(this);
    }
  }
}
