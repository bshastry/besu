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
package org.hyperledger.besu.testfuzz.validator;

import org.hyperledger.besu.testfuzz.StateTestExecutor;
import org.hyperledger.besu.testfuzz.crossvm.CrossVMMetadata;
import org.hyperledger.besu.testfuzz.crossvm.EnhancedCorpusEntry;
import org.hyperledger.besu.testfuzz.tracing.DumpTraceWriter;
import org.hyperledger.besu.testfuzz.tracing.TracingResult;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Worker thread that validates corpus entries against Besu's execution.
 *
 * <p>Each worker has:
 *
 * <ul>
 *   <li>Its own StateTestExecutor (thread-local)
 *   <li>Shared access to job queue and report
 * </ul>
 *
 * <p>Worker loop:
 *
 * <ol>
 *   <li>Poll corpus entry from job queue
 *   <li>Parse and extract cross-VM metadata
 *   <li>Execute test with tracing
 *   <li>Compare trace hashes
 *   <li>Record result in report
 *   <li>Optionally dump traces for divergences
 * </ol>
 */
public class ValidationWorker implements Runnable {

  private static final Logger LOG = LoggerFactory.getLogger(ValidationWorker.class);
  private static final long POLL_TIMEOUT_MS = 100;
  private static final String THIS_CLIENT = "besu";

  private final int workerId;
  private final BlockingQueue<CorpusFile> jobQueue;
  private final ValidationReport report;
  private final AtomicBoolean stopFlag;
  private final String fork;
  private final File traceDumpDir; // May be null if trace dumping is disabled
  private final boolean includeFilteredInDump;

  // Thread-local executor (initialized in run())
  private StateTestExecutor executor;

  /**
   * Creates a new ValidationWorker.
   *
   * @param workerId unique ID for this worker
   * @param jobQueue shared job queue
   * @param report shared validation report
   * @param stopFlag shared stop flag
   * @param fork the EVM fork to use
   */
  public ValidationWorker(
      final int workerId,
      final BlockingQueue<CorpusFile> jobQueue,
      final ValidationReport report,
      final AtomicBoolean stopFlag,
      final String fork) {
    this(workerId, jobQueue, report, stopFlag, fork, null, false);
  }

  /**
   * Creates a new ValidationWorker with trace dump support.
   *
   * @param workerId unique ID for this worker
   * @param jobQueue shared job queue
   * @param report shared validation report
   * @param stopFlag shared stop flag
   * @param fork the EVM fork to use
   * @param traceDumpDir directory for trace dumps (null to disable)
   * @param includeFilteredInDump whether to include filtered entries in dumps
   */
  public ValidationWorker(
      final int workerId,
      final BlockingQueue<CorpusFile> jobQueue,
      final ValidationReport report,
      final AtomicBoolean stopFlag,
      final String fork,
      final File traceDumpDir,
      final boolean includeFilteredInDump) {
    this.workerId = workerId;
    this.jobQueue = jobQueue;
    this.report = report;
    this.stopFlag = stopFlag;
    this.fork = fork;
    this.traceDumpDir = traceDumpDir;
    this.includeFilteredInDump = includeFilteredInDump;
  }

  @Override
  public void run() {
    // Initialize thread-local executor
    this.executor = new StateTestExecutor(fork);

    LOG.debug("ValidationWorker {} started", workerId);

    while (!stopFlag.get() && !Thread.currentThread().isInterrupted()) {
      try {
        CorpusFile job = jobQueue.poll(POLL_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        if (job == null) {
          continue; // No work available, check stop flag
        }

        ValidationResult result = validateFile(job);
        report.recordResult(result);

      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        break;
      } catch (Exception e) {
        LOG.warn("ValidationWorker {} error: {}", workerId, e.getMessage());
      }
    }

    LOG.debug("ValidationWorker {} stopped", workerId);
  }

  /**
   * Validates a single corpus file.
   *
   * @param corpusFile the corpus file to validate
   * @return the validation result
   */
  private ValidationResult validateFile(final CorpusFile corpusFile) {
    String filePath = corpusFile.getPath().toString();

    // Read file contents
    byte[] fileData;
    try {
      fileData = Files.readAllBytes(corpusFile.getPath());
    } catch (IOException e) {
      return ValidationResult.error(filePath, "Failed to read file: " + e.getMessage());
    }

    // Parse as enhanced corpus entry
    EnhancedCorpusEntry entry;
    try {
      entry = EnhancedCorpusEntry.parse(fileData);
    } catch (Exception e) {
      return ValidationResult.error(filePath, "Failed to parse JSON: " + e.getMessage());
    }

    // Check if this is a cross-VM entry we should validate
    if (!entry.shouldVerifyAgainst(THIS_CLIENT)) {
      // No metadata from other client, or it's from Besu itself
      if (!entry.hasMetadata()) {
        return ValidationResult.skipped(filePath, "no cross-VM metadata");
      }
      CrossVMMetadata meta = entry.getMetadata();
      if (meta != null && THIS_CLIENT.equalsIgnoreCase(meta.getGeneratedBy())) {
        return ValidationResult.skipped(filePath, "generated by besu");
      }
      return ValidationResult.skipped(filePath, "no verifiable metadata");
    }

    // Get expected values from metadata
    CrossVMMetadata metadata = entry.getMetadata();
    String expectedHash = metadata.getTraceHash();
    String expectedStateRoot = metadata.getStateRoot();

    if (expectedHash == null || expectedHash.isEmpty()) {
      return ValidationResult.skipped(filePath, "missing traceHash in metadata");
    }

    // Execute test with tracing
    Instant startTime = Instant.now();
    TracingResult besuResult;
    try {
      byte[] testWithoutMetadata = entry.getTestWithoutMetadata();
      besuResult = executor.executeWithTracing(testWithoutMetadata);
    } catch (Exception e) {
      return ValidationResult.error(filePath, "Execution failed: " + e.getMessage());
    }
    Duration executionTime = Duration.between(startTime, Instant.now());

    if (besuResult == null || besuResult.getTraceHash() == null) {
      return ValidationResult.error(filePath, "Execution produced null result");
    }

    // Compare trace hashes
    boolean hashMatch = expectedHash.equals(besuResult.getTraceHash());

    if (hashMatch) {
      // Success!
      return ValidationResult.builder()
          .filePath(filePath)
          .testName(entry.getTestName())
          .status(ValidationResult.Status.PASSED)
          .sourceClient(metadata.getGeneratedBy())
          .sourceVersion(metadata.getVersion())
          .expectedTraceHash(expectedHash)
          .expectedStateRoot(expectedStateRoot)
          .expectedTraceLines(metadata.getTraceLines())
          .actualTraceHash(besuResult.getTraceHash())
          .actualStateRoot(besuResult.getStateRoot())
          .actualTraceLines(besuResult.getTraceLines())
          .executionTime(executionTime)
          .build();
    } else {
      // Divergence detected!
      ValidationResult result =
          ValidationResult.builder()
              .filePath(filePath)
              .testName(entry.getTestName())
              .status(ValidationResult.Status.DIVERGED)
              .sourceClient(metadata.getGeneratedBy())
              .sourceVersion(metadata.getVersion())
              .expectedTraceHash(expectedHash)
              .expectedStateRoot(expectedStateRoot)
              .expectedTraceLines(metadata.getTraceLines())
              .actualTraceHash(besuResult.getTraceHash())
              .actualStateRoot(besuResult.getStateRoot())
              .actualTraceLines(besuResult.getTraceLines())
              .executionTime(executionTime)
              .build();

      // Optionally dump trace for debugging
      if (traceDumpDir != null) {
        dumpTraceForDivergence(entry, corpusFile.getPath());
      }

      return result;
    }
  }

  /**
   * Dumps the trace for a divergent test to aid debugging.
   *
   * @param entry the corpus entry
   * @param sourcePath the source file path
   */
  private void dumpTraceForDivergence(final EnhancedCorpusEntry entry, final Path sourcePath) {
    try {
      String baseName = sourcePath.getFileName().toString();
      if (baseName.endsWith(".json")) {
        baseName = baseName.substring(0, baseName.length() - 5);
      }

      Path dumpPath = traceDumpDir.toPath().resolve(baseName + "_besu.jsonl");

      // Create a tracing executor with dump writer
      DumpTraceWriter dumpWriter =
          new DumpTraceWriter(dumpPath.toString(), includeFilteredInDump, fork);

      StateTestExecutor dumpExecutor = new StateTestExecutor(fork);
      byte[] testWithoutMetadata = entry.getTestWithoutMetadata();

      // Execute with trace dumping
      dumpExecutor.executeWithTracingAndDump(testWithoutMetadata, dumpWriter);

      LOG.debug("Dumped trace to {}", dumpPath);

    } catch (Exception e) {
      LOG.warn("Failed to dump trace for {}: {}", sourcePath, e.getMessage());
    }
  }

  /** Represents a corpus file to be validated. */
  public static class CorpusFile {
    private final Path path;

    public CorpusFile(final Path path) {
      this.path = path;
    }

    public Path getPath() {
      return path;
    }
  }
}
