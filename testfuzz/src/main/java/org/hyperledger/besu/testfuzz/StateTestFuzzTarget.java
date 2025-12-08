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

import org.hyperledger.besu.testfuzz.javafuzz.FuzzTarget;
import org.hyperledger.besu.testfuzz.statetest.CombinedMutationStrategy;
import org.hyperledger.besu.testfuzz.statetest.MutationStrategy;
import org.hyperledger.besu.testfuzz.statetest.StateTestCorpusProvider;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import com.google.common.base.Splitter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fuzz target for Ethereum state tests. Uses custom mutation strategies ported from goevmlab and
 * directly executes tests through Besu's transaction processor.
 *
 * <p>This target is designed for use with both the internal javafuzz framework (JaCoCo-guided) and
 * can be adapted for Jazzer.
 */
public class StateTestFuzzTarget implements FuzzTarget {

  private static final Logger LOG = LoggerFactory.getLogger(StateTestFuzzTarget.class);

  private final StateTestExecutor executor;
  private final CombinedMutationStrategy mutator;
  private final List<byte[]> corpus;

  // Statistics
  private final AtomicLong totalFuzzIterations = new AtomicLong(0);
  private final AtomicLong mutationSuccesses = new AtomicLong(0);
  private final AtomicLong mutationFailures = new AtomicLong(0);
  private final AtomicLong executionCrashes = new AtomicLong(0);

  /**
   * Creates a new StateTestFuzzTarget with a preloaded corpus.
   *
   * @param corpusDirs comma-separated list of corpus directories
   * @param defaultFork the default fork to use for tests
   */
  public StateTestFuzzTarget(final String corpusDirs, final String defaultFork) {
    this.executor = new StateTestExecutor(defaultFork);
    this.corpus = new ArrayList<>();

    if (corpusDirs != null && !corpusDirs.isEmpty()) {
      loadCorpus(corpusDirs);
    }

    // Create mutator with splicing if corpus is available
    if (corpus.size() >= 2) {
      StateTestCorpusProvider corpusProvider = new StateTestCorpusProvider(corpus);
      this.mutator = CombinedMutationStrategy.createWithSplicing(corpusProvider);
      LOG.info(
          "StateTestFuzzTarget initialized with {} corpus entries (splicing enabled)",
          corpus.size());
    } else {
      this.mutator = CombinedMutationStrategy.createDefault();
      LOG.info(
          "StateTestFuzzTarget initialized with {} corpus entries (splicing disabled - need >= 2)",
          corpus.size());
    }
  }

  /** Creates a new StateTestFuzzTarget with default settings. */
  public StateTestFuzzTarget() {
    this(null, "Prague");
  }

  private void loadCorpus(final String dirs) {
    Iterable<String> dirArray = Splitter.on(',').split(dirs);
    for (String dir : dirArray) {
      File file = new File(dir.trim());
      if (file.isDirectory()) {
        loadCorpusDirectory(file);
      } else if (file.isFile() && file.getName().endsWith(".json")) {
        loadCorpusFile(file.toPath());
      }
    }

    // Shuffle for variety
    Collections.shuffle(corpus);
    LOG.info("Loaded {} corpus files", corpus.size());
  }

  private void loadCorpusDirectory(final File dir) {
    File[] files = dir.listFiles();
    if (files == null) {
      return;
    }

    for (File file : files) {
      if (file.isDirectory()) {
        loadCorpusDirectory(file);
      } else if (file.isFile() && file.getName().endsWith(".json")) {
        loadCorpusFile(file.toPath());
      }
    }
  }

  private void loadCorpusFile(final Path path) {
    try {
      byte[] data = Files.readAllBytes(path);
      if (data.length > 0) {
        corpus.add(data);
      }
    } catch (IOException e) {
      LOG.warn("Failed to load corpus file: {}", path, e);
    }
  }

  /**
   * Main fuzz entry point. Called by the fuzzing framework with random/mutated input.
   *
   * @param data the input data (can be random bytes or corpus entry)
   */
  @Override
  public void fuzz(final byte[] data) {
    totalFuzzIterations.incrementAndGet();

    // If we have corpus and input looks like fuzzer entropy, use it to select + mutate
    byte[] testData;
    if (corpus.isEmpty()) {
      // No corpus - use raw input as JSON (probably won't work well)
      testData = data;
    } else if (data.length < 10 || !looksLikeJson(data)) {
      // Input is fuzzer entropy - use it to guide mutation
      testData = mutateCorpusEntry(data);
    } else {
      // Input might be JSON - try to use directly
      testData = data;
    }

    // Execute the test
    try {
      StateTestExecutor.ExecutionResult result = executor.execute(testData);

      if (result.isCrashed()) {
        executionCrashes.incrementAndGet();
        // Throw to signal crash to fuzzer
        throw new RuntimeException("State test crash: " + result.getError());
      }

      // Non-crash errors are fine - they're expected for mutated tests
      if (!result.isSuccess() && LOG.isDebugEnabled()) {
        LOG.debug("Execution error (non-crash): {}", result.getError());
      }

    } catch (RuntimeException e) {
      // Re-throw runtime exceptions (actual crashes)
      throw e;
    } catch (Exception e) {
      // Unexpected exception - could be a bug
      executionCrashes.incrementAndGet();
      throw new RuntimeException("Unexpected exception during fuzzing", e);
    }
  }

  /** Selects a corpus entry and mutates it using fuzzer-provided entropy. */
  private byte[] mutateCorpusEntry(final byte[] entropy) {
    if (corpus.isEmpty()) {
      return entropy;
    }

    // Use entropy to select corpus entry
    int index = Math.abs(bytesToInt(entropy, 0)) % corpus.size();
    byte[] seed = corpus.get(index);

    // Apply mutation
    try {
      MutationStrategy.MutationResult result = mutator.mutate(seed);
      mutationSuccesses.incrementAndGet();
      return result.getData();
    } catch (MutationStrategy.MutationException e) {
      mutationFailures.incrementAndGet();
      // Return original if mutation fails
      return seed;
    }
  }

  private boolean looksLikeJson(final byte[] data) {
    if (data.length < 2) {
      return false;
    }
    // Skip whitespace and check for '{'
    int i = 0;
    while (i < data.length
        && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r')) {
      i++;
    }
    if (i >= data.length) {
      return false;
    }
    return data[i] == '{';
  }

  private int bytesToInt(final byte[] data, final int offset) {
    if (data.length < offset + 4) {
      int result = 0;
      for (int i = offset; i < data.length; i++) {
        result = (result << 8) | (data[i] & 0xFF);
      }
      return result;
    }
    return ((data[offset] & 0xFF) << 24)
        | ((data[offset + 1] & 0xFF) << 16)
        | ((data[offset + 2] & 0xFF) << 8)
        | (data[offset + 3] & 0xFF);
  }

  /**
   * Adds a corpus entry dynamically (e.g., when coverage increases).
   *
   * @param data the corpus entry to add
   */
  public void addCorpusEntry(final byte[] data) {
    corpus.add(data.clone());
  }

  /**
   * Returns statistics string for progress reporting.
   *
   * @return the statistics string
   */
  public String getStats() {
    return String.format(
        "fuzz_iters=%d mutations_ok=%d mutations_fail=%d crashes=%d corpus=%d | %s",
        totalFuzzIterations.get(),
        mutationSuccesses.get(),
        mutationFailures.get(),
        executionCrashes.get(),
        corpus.size(),
        executor.getStats());
  }

  /**
   * Returns the corpus size.
   *
   * @return the corpus size
   */
  public int getCorpusSize() {
    return corpus.size();
  }

  /**
   * Returns the executor for direct access.
   *
   * @return the executor
   */
  public StateTestExecutor getExecutor() {
    return executor;
  }

  /**
   * Returns the mutator for direct access.
   *
   * @return the mutator
   */
  public CombinedMutationStrategy getMutator() {
    return mutator;
  }
}
