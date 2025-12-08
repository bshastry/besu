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

import org.hyperledger.besu.testfuzz.StateTestExecutor;
import org.hyperledger.besu.testfuzz.statetest.CombinedMutationStrategy;
import org.hyperledger.besu.testfuzz.statetest.MutationStrategy;
import org.hyperledger.besu.testfuzz.statetest.StateTestCorpusProvider;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Worker thread that performs coverage-guided fuzzing.
 *
 * <p>Each worker has:
 *
 * <ul>
 *   <li>Its own StateTestExecutor (thread-safe, has internal stats)
 *   <li>Its own CombinedMutationStrategy (uses ThreadLocalRandom)
 *   <li>Shared access to InputQueue and CoverageTracker
 * </ul>
 *
 * <p>Worker loop:
 *
 * <ol>
 *   <li>Poll entry from InputQueue
 *   <li>Apply mutation
 *   <li>Execute test
 *   <li>Check for new coverage
 *   <li>If interesting, add mutated input to queue
 *   <li>Requeue original entry
 * </ol>
 */
public class FuzzWorker implements Runnable {

  private static final Logger LOG = LoggerFactory.getLogger(FuzzWorker.class);

  private static final int DEFAULT_MUTATIONS_PER_ENTRY = 8;
  private static final int DEFAULT_COVERAGE_CHECK_INTERVAL = 1;
  private static final long POLL_TIMEOUT_MS = 100;

  private final int workerId;
  private final InputQueue inputQueue;
  private final CoverageTracker coverageTracker;
  private final CrashManager crashManager;
  private final AtomicBoolean stopFlag;
  private final String fork;
  private final List<byte[]> corpusForSplicing;

  // Thread-local components (initialized in run())
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

  /**
   * Creates a new FuzzWorker.
   *
   * @param workerId unique ID for this worker
   * @param inputQueue shared input queue
   * @param coverageTracker shared coverage tracker
   * @param crashManager shared crash manager
   * @param stopFlag shared stop flag
   * @param fork the EVM fork to use
   * @param corpusForSplicing shared corpus for splicing mutations
   */
  public FuzzWorker(
      final int workerId,
      final InputQueue inputQueue,
      final CoverageTracker coverageTracker,
      final CrashManager crashManager,
      final AtomicBoolean stopFlag,
      final String fork,
      final List<byte[]> corpusForSplicing) {
    this.workerId = workerId;
    this.inputQueue = inputQueue;
    this.coverageTracker = coverageTracker;
    this.crashManager = crashManager;
    this.stopFlag = stopFlag;
    this.fork = fork;
    this.corpusForSplicing = corpusForSplicing;
    this.mutationsPerEntry = DEFAULT_MUTATIONS_PER_ENTRY;
    this.coverageCheckInterval = DEFAULT_COVERAGE_CHECK_INTERVAL;
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

    LOG.debug("Worker {} started", workerId);

    // Main fuzzing loop
    while (!stopFlag.get() && !Thread.currentThread().isInterrupted()) {
      try {
        // Poll with timeout to check stop flag periodically
        CorpusEntry entry = inputQueue.poll(POLL_TIMEOUT_MS, TimeUnit.MILLISECONDS);
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
        LOG.warn("Worker {} error: {}", workerId, e.getMessage());
      }
    }

    LOG.debug("Worker {} stopped", workerId);
  }

  private void processEntry(final CorpusEntry entry) {
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
   *
   * @return statistics string
   */
  public String getStats() {
    return String.format(
        "worker[%d]: iters=%d cov_hits=%d mut_fail=%d exec_err=%d",
        workerId,
        iterations.get(),
        coverageHits.get(),
        mutationFailures.get(),
        executionErrors.get());
  }

  /**
   * Returns the worker ID.
   *
   * @return worker ID
   */
  public int getWorkerId() {
    return workerId;
  }

  /**
   * Returns the number of iterations performed.
   *
   * @return iterations
   */
  public long getIterations() {
    return iterations.get();
  }

  /**
   * Returns the number of coverage hits found.
   *
   * @return coverage hits
   */
  public long getCoverageHits() {
    return coverageHits.get();
  }

  /**
   * Returns the number of mutation failures.
   *
   * @return mutation failures
   */
  public long getMutationFailures() {
    return mutationFailures.get();
  }

  /**
   * Returns the number of execution errors.
   *
   * @return execution errors
   */
  public long getExecutionErrors() {
    return executionErrors.get();
  }
}
