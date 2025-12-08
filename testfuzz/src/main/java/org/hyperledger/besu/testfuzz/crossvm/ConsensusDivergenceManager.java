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
package org.hyperledger.besu.testfuzz.crossvm;

import org.hyperledger.besu.testfuzz.tracing.TracingResult;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages consensus divergence detection and reporting for cross-VM comparison. Saves divergences
 * to disk and maintains statistics compatible with geth's fuzzer format.
 *
 * <p>Output files:
 *
 * <ul>
 *   <li>divergence_N.json - Raw test input that caused divergence
 *   <li>crossvm_divergences.log - Append-only log of all divergences
 *   <li>divergence_report_N.json (optional) - Extended report with comparison details
 * </ul>
 */
public class ConsensusDivergenceManager {

  private static final Logger LOG = LoggerFactory.getLogger(ConsensusDivergenceManager.class);
  private static final String LOG_FILE = "crossvm_divergences.log";
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final File crashDir;
  private final Path logFilePath;
  private final Set<String> seenPairs; // "hash1:hash2" for deduplication
  private final AtomicLong totalVerified;
  private final AtomicLong totalDivergences;
  private final AtomicLong uniqueDivergences;
  private final Object fileLock = new Object();

  private final String besuVersion;

  /**
   * Creates a new ConsensusDivergenceManager.
   *
   * @param crashDir the directory to save divergence files
   * @param besuVersion the current Besu version string
   * @throws IOException if the directory cannot be created
   */
  public ConsensusDivergenceManager(final File crashDir, final String besuVersion)
      throws IOException {
    this.crashDir = crashDir;
    this.besuVersion = besuVersion;
    this.logFilePath = crashDir.toPath().resolve(LOG_FILE);
    this.seenPairs = ConcurrentHashMap.newKeySet();
    this.totalVerified = new AtomicLong(0);
    this.totalDivergences = new AtomicLong(0);
    this.uniqueDivergences = new AtomicLong(0);

    if (!crashDir.exists() && !crashDir.mkdirs()) {
      throw new IOException("Failed to create crash directory: " + crashDir);
    }
  }

  /** Records a successful cross-VM verification (hashes matched). */
  public void recordVerified() {
    totalVerified.incrementAndGet();
  }

  /**
   * Records and saves a consensus divergence.
   *
   * @param entry the corpus entry that caused the divergence
   * @param besuResult the result from Besu's execution
   * @param workerId the worker thread ID
   * @return true if this is a new unique divergence, false if duplicate
   */
  public boolean saveDivergence(
      final EnhancedCorpusEntry entry, final TracingResult besuResult, final int workerId) {

    CrossVMMetadata otherMeta = entry.getMetadata();
    if (otherMeta == null) {
      return false;
    }

    totalDivergences.incrementAndGet();

    // Check for duplicate
    String pairKey = otherMeta.getTraceHash() + ":" + besuResult.getTraceHash();
    if (!seenPairs.add(pairKey)) {
      return false; // Duplicate
    }

    int divergenceId = (int) uniqueDivergences.incrementAndGet();

    synchronized (fileLock) {
      try {
        // 1. Save raw test input
        saveDivergenceFile(entry.getTestRaw(), divergenceId);

        // 2. Append to log file
        logDivergence(
            divergenceId,
            otherMeta.getGeneratedBy(),
            otherMeta.getTraceHash(),
            besuResult.getTraceHash());

        // 3. Save extended report
        saveExtendedReport(divergenceId, entry, otherMeta, besuResult, workerId);

        LOG.warn(
            "[CONSENSUS DIVERGENCE #{}] {} expected={} besu={}",
            divergenceId,
            otherMeta.getGeneratedBy(),
            otherMeta.getTraceHash().substring(0, Math.min(8, otherMeta.getTraceHash().length())),
            besuResult
                .getTraceHash()
                .substring(0, Math.min(8, besuResult.getTraceHash().length())));

        return true;
      } catch (IOException e) {
        LOG.error("Failed to save divergence #{}: {}", divergenceId, e.getMessage());
        return false;
      }
    }
  }

  /**
   * Saves the raw test input file.
   *
   * @param testInput the raw JSON bytes
   * @param divergenceId the divergence ID
   */
  private void saveDivergenceFile(final byte[] testInput, final int divergenceId)
      throws IOException {
    Path file = crashDir.toPath().resolve(String.format("divergence_%d.json", divergenceId));
    Files.write(file, testInput);
  }

  /**
   * Appends a log entry to the divergence log file.
   *
   * @param divergenceId the divergence ID
   * @param sourceClient the client that generated the corpus entry
   * @param expectedHash the expected trace hash
   * @param actualHash the actual trace hash from Besu
   */
  private void logDivergence(
      final int divergenceId,
      final String sourceClient,
      final String expectedHash,
      final String actualHash)
      throws IOException {
    String entry =
        String.format(
            "[%s] CONSENSUS DIVERGENCE #%d: source=%s expected=%s actual=%s%n",
            Instant.now().toString(), divergenceId, sourceClient, expectedHash, actualHash);

    Files.write(
        logFilePath,
        entry.getBytes(StandardCharsets.UTF_8),
        StandardOpenOption.CREATE,
        StandardOpenOption.APPEND);
  }

  /**
   * Saves an extended report with full comparison details.
   *
   * @param divergenceId the divergence ID
   * @param entry the corpus entry
   * @param otherMeta the metadata from the other client
   * @param besuResult the result from Besu
   * @param workerId the worker ID
   */
  private void saveExtendedReport(
      final int divergenceId,
      final EnhancedCorpusEntry entry,
      final CrossVMMetadata otherMeta,
      final TracingResult besuResult,
      final int workerId)
      throws IOException {

    ObjectNode report = OBJECT_MAPPER.createObjectNode();
    report.put("divergenceId", divergenceId);
    report.put("detectedAt", Instant.now().toString());
    report.put("workerId", workerId);

    // Parse and include test without metadata
    try {
      report.set("test", OBJECT_MAPPER.readTree(entry.getTestWithoutMetadata()));
    } catch (Exception e) {
      report.put("testRaw", new String(entry.getTestWithoutMetadata(), StandardCharsets.UTF_8));
    }

    // Source client info
    ObjectNode source = OBJECT_MAPPER.createObjectNode();
    source.put("client", otherMeta.getGeneratedBy());
    source.put("version", otherMeta.getVersion());
    source.put("traceHash", otherMeta.getTraceHash());
    source.put("stateRoot", otherMeta.getStateRoot());
    source.put("traceLines", otherMeta.getTraceLines());
    report.set("source", source);

    // Besu info
    ObjectNode besu = OBJECT_MAPPER.createObjectNode();
    besu.put("client", "besu");
    besu.put("version", besuVersion);
    besu.put("traceHash", besuResult.getTraceHash());
    besu.put("stateRoot", besuResult.getStateRoot());
    besu.put("traceLines", besuResult.getTraceLines());
    report.set("besu", besu);

    Path file = crashDir.toPath().resolve(String.format("divergence_report_%d.json", divergenceId));
    OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), report);
  }

  /**
   * Gets the number of successful cross-VM verifications.
   *
   * @return the verified count
   */
  public long getVerifiedCount() {
    return totalVerified.get();
  }

  /**
   * Gets the total number of divergences (including duplicates).
   *
   * @return the total divergence count
   */
  public long getTotalDivergences() {
    return totalDivergences.get();
  }

  /**
   * Gets the number of unique divergences.
   *
   * @return the unique divergence count
   */
  public long getUniqueDivergences() {
    return uniqueDivergences.get();
  }

  /**
   * Returns a statistics string for progress reporting.
   *
   * @return formatted statistics
   */
  public String getStats() {
    return String.format(
        "crossvm_verified=%d crossvm_diverged=%d", totalVerified.get(), uniqueDivergences.get());
  }

  /** Prints the final summary to the console. */
  public void printFinalSummary() {
    System.out.println();
    System.out.println("=== Cross-VM Consensus Verification ===");
    System.out.println("Verified: " + totalVerified.get());
    System.out.println("Divergences: " + uniqueDivergences.get());

    if (uniqueDivergences.get() > 0) {
      System.out.println();
      System.out.println("CONSENSUS DIVERGENCES DETECTED!");
      System.out.println("Divergence files: " + crashDir.getPath() + "/divergence_*.json");
      System.out.println("Divergence log: " + logFilePath);
    }
  }
}
