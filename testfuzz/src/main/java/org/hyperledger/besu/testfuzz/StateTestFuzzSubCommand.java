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
package org.hyperledger.besu.testfuzz;

import org.hyperledger.besu.testfuzz.javafuzz.Fuzzer;
import org.hyperledger.besu.testfuzz.statetest.CombinedMutationStrategy;
import org.hyperledger.besu.testfuzz.statetest.MutationStrategy;
import org.hyperledger.besu.testfuzz.statetest.StateTestCorpusProvider;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.tuweni.bytes.Bytes;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParentCommand;

/**
 * CLI subcommand for state test fuzzing.
 * Fuzzes Besu's EVM implementation using state tests with goevmlab-style mutations.
 */
@Command(
    name = "state-test-fuzz",
    description = "Fuzz Besu's EVM with state test mutations",
    mixinStandardHelpOptions = true,
    versionProvider = VersionProvider.class)
public class StateTestFuzzSubCommand implements Runnable {

  @SuppressWarnings("UnusedVariable")
  @ParentCommand
  private BesuFuzzCommand parentCommand;

  @Option(
      names = {"--corpus-dir"},
      description = "Directory containing state test corpus (JSON files)",
      required = true)
  private String corpusDir;

  @Option(
      names = {"--new-corpus-dir"},
      description = "Directory to save new corpus entries that increase coverage")
  private File newCorpusDir;

  @Option(
      names = {"--crash-dir"},
      description = "Directory to save crash files",
      defaultValue = "crashes")
  private File crashDir;

  @Option(
      names = {"--fork"},
      description = "Default fork to use for tests",
      defaultValue = "Prague")
  private String fork;

  @Option(
      names = {"--duration"},
      description = "Fuzzing duration (e.g., 1h, 30m, infinite)",
      defaultValue = "infinite")
  private String duration;

  @Option(
      names = {"--guidance-regexp"},
      description = "Regexp for classes to track for coverage guidance")
  private String guidanceRegexp;

  @Option(
      names = {"--workers", "-w"},
      description = "Number of worker threads (default: number of CPU cores)",
      defaultValue = "0")
  private int workers;

  // Shared state for multi-threaded fuzzing
  private final AtomicLong totalIterations = new AtomicLong(0);
  private final AtomicLong totalCrashes = new AtomicLong(0);
  private final AtomicBoolean stopFlag = new AtomicBoolean(false);
  private List<byte[]> corpus;

  /**
   * Default constructor for PicoCLI.
   */
  public StateTestFuzzSubCommand() {
    // Required by PicoCLI
  }

  @Override
  public void run() {
    System.out.println("=== Besu State Test Fuzzer ===");
    System.out.println();

    // Create crash directory
    if (!crashDir.exists()) {
      crashDir.mkdirs();
    }

    // Create the fuzz target
    StateTestFuzzTarget target = new StateTestFuzzTarget(corpusDir, fork);

    System.out.printf("Corpus: %d files%n", target.getCorpusSize());
    System.out.printf("Fork: %s%n", fork);
    System.out.printf("Crash dir: %s%n", crashDir.getAbsolutePath());
    if (newCorpusDir != null) {
      System.out.printf("New corpus dir: %s%n", newCorpusDir.getAbsolutePath());
    }
    System.out.println();

    if (target.getCorpusSize() == 0) {
      System.err.println("Error: No corpus files found in " + corpusDir);
      System.exit(1);
    }

    // Parse duration
    Duration fuzzDuration = parseDuration(duration);

    // Start fuzzing
    try {
      if (guidanceRegexp != null && !guidanceRegexp.isEmpty()) {
        // Use JaCoCo-guided fuzzing
        runGuidedFuzzing(target, fuzzDuration);
      } else {
        // Use simple fuzzing without coverage guidance
        runSimpleFuzzing(target, fuzzDuration);
      }
    } catch (Exception e) {
      System.err.println("Fuzzing error: " + e.getMessage());
      e.printStackTrace();
      System.exit(1);
    }
  }

  private void runGuidedFuzzing(final StateTestFuzzTarget target, final Duration fuzzDuration)
      throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException,
      IllegalAccessException, NoSuchAlgorithmException {

    System.out.println("Starting JaCoCo-guided fuzzing...");
    System.out.printf("Guidance regexp: %s%n", guidanceRegexp);
    System.out.println();

    Fuzzer fuzzer = new Fuzzer(
        target,
        corpusDir,
        target::getStats,
        guidanceRegexp,
        newCorpusDir
    );

    // Set up duration limit if not infinite
    if (fuzzDuration != null) {
      Instant deadline = Instant.now().plus(fuzzDuration);
      Thread shutdownThread = new Thread(() -> {
        while (Instant.now().isBefore(deadline)) {
          try {
            Thread.sleep(1000);
          } catch (InterruptedException e) {
            break;
          }
        }
        System.out.println("\nDuration limit reached. Stopping...");
        System.exit(0);
      });
      shutdownThread.setDaemon(true);
      shutdownThread.start();
    }

    fuzzer.start();
  }

  @SuppressWarnings("UnusedVariable") // target passed for API consistency with guided fuzzing
  private void runSimpleFuzzing(final StateTestFuzzTarget target, final Duration fuzzDuration) {
    int numWorkers = workers > 0 ? workers : Runtime.getRuntime().availableProcessors();
    System.out.printf("Starting multi-threaded fuzzing with %d workers...%n", numWorkers);
    System.out.println();

    // Load corpus into shared list
    corpus = loadCorpusFiles(corpusDir);
    if (corpus.isEmpty()) {
      System.err.println("Error: No corpus files loaded");
      System.exit(1);
    }
    System.out.printf("Loaded %d corpus files%n", corpus.size());

    Instant startTime = Instant.now();
    Instant deadline = fuzzDuration != null ? startTime.plus(fuzzDuration) : null;

    // Create executor service
    ExecutorService executor = Executors.newFixedThreadPool(numWorkers);
    CountDownLatch latch = new CountDownLatch(numWorkers);

    // Start worker threads
    for (int i = 0; i < numWorkers; i++) {
      final int workerId = i;
      executor.submit(() -> {
        try {
          runWorker(workerId, deadline);
        } finally {
          latch.countDown();
        }
      });
    }

    // Progress reporter thread
    Thread reporter = new Thread(() -> {
      // Tracking progress
      while (!stopFlag.get()) {
        try {
          Thread.sleep(3000);
        } catch (InterruptedException e) {
          break;
        }

        Instant now = Instant.now();
        Duration elapsed = Duration.between(startTime, now);
        long iters = totalIterations.get();
        long crashes = totalCrashes.get();
        double rate = iters / (elapsed.getSeconds() + 0.001);

        System.out.printf("elapsed: %s | execs: %d (%.1f/sec) | crashes: %d | workers: %d%n",
            formatDuration(elapsed), iters, rate, crashes, numWorkers);
      }
    });
    reporter.setDaemon(true);
    reporter.start();

    // Wait for duration or shutdown
    try {
      if (deadline != null) {
        long remainingMs = Duration.between(Instant.now(), deadline).toMillis();
        if (remainingMs > 0) {
          latch.await(remainingMs, TimeUnit.MILLISECONDS);
        }
        stopFlag.set(true);
      } else {
        latch.await();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }

    stopFlag.set(true);
    executor.shutdownNow();

    Duration elapsed = Duration.between(startTime, Instant.now());
    System.out.println();
    System.out.println("=== Final Results ===");
    System.out.printf("Duration: %s%n", formatDuration(elapsed));
    System.out.printf("Workers: %d%n", numWorkers);
    System.out.printf("Iterations: %d%n", totalIterations.get());
    System.out.printf("Rate: %.1f/sec%n", totalIterations.get() / (elapsed.getSeconds() + 0.001));
    System.out.printf("Crashes: %d%n", totalCrashes.get());
  }

  /**
   * Worker thread that performs fuzzing.
   * Each worker has its own executor and mutator for thread safety.
   */
  private void runWorker(final int workerId, final Instant deadline) {
    // Each worker gets its own executor and mutator (thread-local)
    StateTestExecutor workerExecutor = new StateTestExecutor(fork);

    // Create mutator with splicing if corpus is available
    CombinedMutationStrategy workerMutator;
    if (corpus.size() >= 2) {
      StateTestCorpusProvider corpusProvider = new StateTestCorpusProvider(corpus);
      workerMutator = CombinedMutationStrategy.createWithSplicing(corpusProvider);
    } else {
      workerMutator = CombinedMutationStrategy.createDefault();
    }

    Random rng = new Random(System.nanoTime() + workerId);

    while (!stopFlag.get() && (deadline == null || Instant.now().isBefore(deadline))) {
      // Select random corpus entry
      byte[] seed = corpus.get(rng.nextInt(corpus.size()));

      // Apply mutation
      byte[] mutated;
      try {
        MutationStrategy.MutationResult result = workerMutator.mutate(seed);
        mutated = result.getData();
      } catch (MutationStrategy.MutationException e) {
        mutated = seed; // Use original if mutation fails
      }

      // Execute
      try {
        StateTestExecutor.ExecutionResult result = workerExecutor.execute(mutated);
        totalIterations.incrementAndGet();

        if (result.isCrashed()) {
          totalCrashes.incrementAndGet();
          saveCrashBytes(mutated, result.getError());
        }
      } catch (Exception e) {
        totalIterations.incrementAndGet();
        totalCrashes.incrementAndGet();
        saveCrashBytes(mutated, e.getMessage());
      }
    }
  }

  /**
   * Loads corpus files from directory.
   */
  private List<byte[]> loadCorpusFiles(final String dir) {
    List<byte[]> files = new ArrayList<>();
    loadCorpusRecursive(new File(dir), files);
    Collections.shuffle(files);
    return files;
  }

  private void loadCorpusRecursive(final File dir, final List<byte[]> files) {
    if (!dir.exists()) {
      return;
    }

    if (dir.isFile() && dir.getName().endsWith(".json")) {
      try {
        byte[] data = Files.readAllBytes(dir.toPath());
        if (data.length > 0) {
          files.add(data);
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
        loadCorpusRecursive(child, files);
      } else if (child.getName().endsWith(".json")) {
        try {
          byte[] data = Files.readAllBytes(child.toPath());
          if (data.length > 0) {
            files.add(data);
          }
        } catch (IOException e) {
          // Skip unreadable files
        }
      }
    }
  }

  /**
   * Saves crash with the actual mutated JSON bytes.
   */
  private synchronized void saveCrashBytes(final byte[] testData, final String error) {
    try {
      String hash = String.format("%08x", java.util.Arrays.hashCode(testData));
      String filename = String.format("crash-%d-%s.json", System.currentTimeMillis(), hash);
      File crashFile = new File(crashDir, filename);

      try (FileOutputStream fos = new FileOutputStream(crashFile)) {
        fos.write(testData);
      }

      // Create metadata file
      String metaFilename = filename.replace(".json", ".txt");
      File metaFile = new File(crashDir, metaFilename);
      try (FileOutputStream fos = new FileOutputStream(metaFile)) {
        String meta = String.format("Crash at %s%nError: %s%n",
            Instant.now(),
            error != null ? error : "unknown"
        );
        fos.write(meta.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      }

      System.out.printf("[!] Crash saved to %s%n", crashFile.getName());

    } catch (IOException ioe) {
      System.err.println("Failed to save crash: " + ioe.getMessage());
    }
  }

  private Duration parseDuration(final String durationStr) {
    if (durationStr == null || durationStr.equalsIgnoreCase("infinite")) {
      return null;
    }

    String normalizedDuration = durationStr.toLowerCase(java.util.Locale.ROOT).trim();

    try {
      if (normalizedDuration.endsWith("h")) {
        return Duration.ofHours(Long.parseLong(normalizedDuration.substring(0, normalizedDuration.length() - 1)));
      } else if (normalizedDuration.endsWith("m")) {
        return Duration.ofMinutes(Long.parseLong(normalizedDuration.substring(0, normalizedDuration.length() - 1)));
      } else if (normalizedDuration.endsWith("s")) {
        return Duration.ofSeconds(Long.parseLong(normalizedDuration.substring(0, normalizedDuration.length() - 1)));
      } else {
        // Assume seconds
        return Duration.ofSeconds(Long.parseLong(normalizedDuration));
      }
    } catch (NumberFormatException e) {
      System.err.println("Invalid duration format: " + normalizedDuration);
      return null;
    }
  }

  private String formatDuration(final Duration duration) {
    long hours = duration.toHours();
    long minutes = duration.toMinutesPart();
    long seconds = duration.toSecondsPart();
    return String.format("%02d:%02d:%02d", hours, minutes, seconds);
  }
}
