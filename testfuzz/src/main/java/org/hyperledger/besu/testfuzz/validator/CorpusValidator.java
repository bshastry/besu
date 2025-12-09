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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;


/**
 * High-performance parallel corpus validator for cross-VM consensus verification.
 *
 * <p>This is the main entry point for validating a geth-produced enhanced corpus against Besu's
 * execution. It:
 *
 * <ul>
 *   <li>Loads all .json files from the corpus directory
 *   <li>Spawns worker threads (virtual threads on Java 21+)
 *   <li>Validates each file's trace hash against Besu's execution
 *   <li>Produces a detailed report of matches and divergences
 * </ul>
 *
 * <p>Usage:
 *
 * <pre>{@code
 * CorpusValidator validator = new CorpusValidator.Builder()
 *     .corpusDir(new File("/path/to/corpus"))
 *     .fork("Prague")
 *     .workers(16)
 *     .build();
 *
 * ValidationReport report = validator.validate();
 * report.printConsoleSummary();
 * }</pre>
 */
public class CorpusValidator {

  private static final int PROGRESS_INTERVAL_MS = 3000;
  private static final int SHUTDOWN_TIMEOUT_SECONDS = 30;
  private static final int QUEUE_CAPACITY = 10000;

  private final File corpusDir;
  private final String fork;
  private final int numWorkers;
  private final File traceDumpDir;
  private final boolean includeFilteredInDump;
  private final boolean quiet;

  private CorpusValidator(final Builder builder) {
    this.corpusDir = builder.corpusDir;
    this.fork = builder.fork != null ? builder.fork : "Prague";
    this.numWorkers =
        builder.numWorkers > 0 ? builder.numWorkers : Runtime.getRuntime().availableProcessors();
    this.traceDumpDir = builder.traceDumpDir;
    this.includeFilteredInDump = builder.includeFilteredInDump;
    this.quiet = builder.quiet;
  }

  /**
   * Validates all corpus entries and returns the report.
   *
   * @return the validation report
   * @throws IOException if corpus cannot be loaded
   */
  public ValidationReport validate() throws IOException {
    // Load corpus files
    List<Path> corpusFiles = loadCorpusFiles();

    if (corpusFiles.isEmpty()) {
      throw new IOException("No .json files found in corpus directory: " + corpusDir);
    }

    if (!quiet) {
      System.out.println("=== Cross-VM Corpus Validator ===");
      System.out.println();
      System.out.printf("Corpus:  %s%n", corpusDir.getAbsolutePath());
      System.out.printf("Files:   %d%n", corpusFiles.size());
      System.out.printf("Fork:    %s%n", fork);
      System.out.printf("Workers: %d%n", numWorkers);
      if (traceDumpDir != null) {
        System.out.printf("Dumps:   %s%n", traceDumpDir.getAbsolutePath());
      }
      System.out.println();
    }

    // Create report
    ValidationReport report = new ValidationReport(corpusDir.getAbsolutePath(), fork, numWorkers);

    // Create job queue
    BlockingQueue<ValidationWorker.CorpusFile> jobQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);

    // Create stop flag
    AtomicBoolean stopFlag = new AtomicBoolean(false);

    // Create trace dump directory if needed
    if (traceDumpDir != null && !traceDumpDir.exists()) {
      traceDumpDir.mkdirs();
    }

    // Start workers
    ExecutorService executorService = Executors.newVirtualThreadPerTaskExecutor();

    for (int i = 0; i < numWorkers; i++) {
      ValidationWorker worker =
          new ValidationWorker(
              i, jobQueue, report, stopFlag, fork, traceDumpDir, includeFilteredInDump);
      executorService.submit(worker);
    }

    // Start progress reporter
    Thread progressThread = null;
    if (!quiet) {
      progressThread =
          Thread.ofVirtual()
              .start(
                  () -> {
                    while (!stopFlag.get() && !Thread.currentThread().isInterrupted()) {
                      try {
                        Thread.sleep(PROGRESS_INTERVAL_MS);
                        System.out.println(report.getProgressString());
                      } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                      }
                    }
                  });
    }

    // Enqueue all jobs
    for (Path path : corpusFiles) {
      try {
        jobQueue.put(new ValidationWorker.CorpusFile(path));
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        break;
      }
    }

    // Wait for queue to drain
    while (!jobQueue.isEmpty() && !stopFlag.get()) {
      try {
        Thread.sleep(100);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        break;
      }
    }

    // Signal stop and wait for workers
    stopFlag.set(true);

    if (progressThread != null) {
      progressThread.interrupt();
    }

    executorService.shutdown();
    try {
      if (!executorService.awaitTermination(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
        executorService.shutdownNow();
      }
    } catch (InterruptedException e) {
      executorService.shutdownNow();
      Thread.currentThread().interrupt();
    }

    // Print final report
    if (!quiet) {
      report.printConsoleSummary();
    }

    return report;
  }

  /**
   * Loads all .json files from the corpus directory.
   *
   * @return list of file paths
   * @throws IOException if directory cannot be read
   */
  private List<Path> loadCorpusFiles() throws IOException {
    List<Path> files = new ArrayList<>();

    if (!corpusDir.exists()) {
      throw new IOException("Corpus directory does not exist: " + corpusDir);
    }

    if (!corpusDir.isDirectory()) {
      // Single file mode
      if (corpusDir.getName().endsWith(".json")) {
        files.add(corpusDir.toPath());
      }
      return files;
    }

    // Recursively find all .json files
    try (Stream<Path> paths = Files.walk(corpusDir.toPath())) {
      paths
          .filter(Files::isRegularFile)
          .filter(p -> p.toString().endsWith(".json"))
          .forEach(files::add);
    }

    return files;
  }

  /** Builder for CorpusValidator. */
  public static class Builder {
    private File corpusDir;
    private String fork = "Prague";
    private int numWorkers = 0; // 0 = auto-detect
    private File traceDumpDir;
    private boolean includeFilteredInDump = false;
    private boolean quiet = false;

    /**
     * Sets the corpus directory.
     *
     * @param dir the corpus directory
     * @return this builder
     */
    public Builder corpusDir(final File dir) {
      this.corpusDir = dir;
      return this;
    }

    /**
     * Sets the EVM fork.
     *
     * @param fork the fork name
     * @return this builder
     */
    public Builder fork(final String fork) {
      this.fork = fork;
      return this;
    }

    /**
     * Sets the number of worker threads.
     *
     * @param n number of workers (0 for auto-detect)
     * @return this builder
     */
    public Builder workers(final int n) {
      this.numWorkers = n;
      return this;
    }

    /**
     * Sets the trace dump directory for divergent tests.
     *
     * @param dir the dump directory
     * @return this builder
     */
    public Builder traceDumpDir(final File dir) {
      this.traceDumpDir = dir;
      return this;
    }

    /**
     * Sets whether to include filtered entries in trace dumps.
     *
     * @param include true to include filtered entries
     * @return this builder
     */
    public Builder includeFilteredInDump(final boolean include) {
      this.includeFilteredInDump = include;
      return this;
    }

    /**
     * Sets quiet mode.
     *
     * @param q true for quiet output (JSON only)
     * @return this builder
     */
    public Builder quiet(final boolean q) {
      this.quiet = q;
      return this;
    }

    /**
     * Builds the CorpusValidator.
     *
     * @return a new CorpusValidator instance
     */
    public CorpusValidator build() {
      if (corpusDir == null) {
        throw new IllegalStateException("corpusDir is required");
      }
      return new CorpusValidator(this);
    }
  }
}
