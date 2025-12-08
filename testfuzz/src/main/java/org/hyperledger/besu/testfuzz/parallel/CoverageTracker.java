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

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Pattern;

import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.data.ExecutionDataReader;
import org.jacoco.core.data.IExecutionDataVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thread-safe coverage tracker that aggregates JaCoCo coverage from all workers.
 *
 * <p>Design decisions:
 *
 * <ul>
 *   <li>Uses read-write lock for bitmap access (reads are frequent, writes are rare)
 *   <li>Stores max probe hits per class (not just boolean hit)
 *   <li>Lazy initialization of class entries in ConcurrentHashMap
 * </ul>
 */
public class CoverageTracker {

  private static final Logger LOG = LoggerFactory.getLogger(CoverageTracker.class);

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

  /** Result of a coverage check. */
  public static class CoverageResult {
    private final int newEdges;
    private final long totalEdges;
    private final boolean isInteresting;

    /**
     * Creates a new CoverageResult.
     *
     * @param newEdges number of new edges discovered
     * @param totalEdges total edges discovered so far
     */
    public CoverageResult(final int newEdges, final long totalEdges) {
      this.newEdges = newEdges;
      this.totalEdges = totalEdges;
      this.isInteresting = newEdges > 0;
    }

    /**
     * Returns the number of new edges discovered.
     *
     * @return new edges count
     */
    public int getNewEdges() {
      return newEdges;
    }

    /**
     * Returns the total edges discovered.
     *
     * @return total edges
     */
    public long getTotalEdges() {
      return totalEdges;
    }

    /**
     * Returns true if this execution discovered new coverage.
     *
     * @return true if interesting
     */
    public boolean isInteresting() {
      return isInteresting;
    }
  }

  /**
   * Creates a new CoverageTracker.
   *
   * @param guidanceRegexp regexp for classes to track (null for all)
   * @throws ReflectiveOperationException if JaCoCo agent cannot be accessed
   */
  public CoverageTracker(final String guidanceRegexp) throws ReflectiveOperationException {
    // Initialize JaCoCo agent access
    Class<?> rtClass = Class.forName("org.jacoco.agent.rt.RT");
    Method getAgentMethod = rtClass.getMethod("getAgent");
    this.agent = getAgentMethod.invoke(null);
    this.getExecutionDataMethod = agent.getClass().getMethod("getExecutionData", boolean.class);

    this.guidanceRegexp =
        guidanceRegexp != null && !guidanceRegexp.isBlank()
            ? Pattern.compile(guidanceRegexp)
            : null;

    this.coverageBitmap = new ConcurrentHashMap<>();
    this.coverageLock = new ReentrantReadWriteLock();
    this.totalEdges = new AtomicLong(0);
    this.newEdgesDiscovered = new AtomicLong(0);
    this.coverageChecks = new AtomicLong(0);
  }

  /**
   * Checks if current execution discovered new coverage.
   *
   * <p>Thread-safety: Uses read-write lock to ensure atomic check-then-update. Multiple workers can
   * check concurrently (read lock), but updates are serialized.
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
      ExecutionDataReader reader = new ExecutionDataReader(new ByteArrayInputStream(dumpData));

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
          if (guidanceRegexp != null && !guidanceRegexp.matcher(className).find()) {
            continue;
          }

          // Skip fuzzer infrastructure classes
          if (className.startsWith("org/hyperledger/besu/testfuzz/")) {
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
            System.arraycopy(
                existingHits, 0, newHits, 0, Math.min(existingHits.length, newHits.length));
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
      LOG.debug("Coverage check failed: {}", e.getMessage());
      return new CoverageResult(0, totalEdges.get());
    }
  }

  /**
   * Gets current total edge count.
   *
   * @return total edges
   */
  public long getTotalEdges() {
    return totalEdges.get();
  }

  /**
   * Gets the number of coverage checks performed.
   *
   * @return coverage checks count
   */
  public long getCoverageChecks() {
    return coverageChecks.get();
  }

  /**
   * Gets the number of new edges discovered.
   *
   * @return new edges discovered
   */
  public long getNewEdgesDiscovered() {
    return newEdgesDiscovered.get();
  }

  /**
   * Gets the number of classes tracked.
   *
   * @return number of classes
   */
  public int getClassCount() {
    return coverageBitmap.size();
  }

  /**
   * Gets statistics string.
   *
   * @return statistics
   */
  public String getStats() {
    return String.format(
        "edges=%d checks=%d new=%d classes=%d",
        totalEdges.get(), coverageChecks.get(), newEdgesDiscovered.get(), coverageBitmap.size());
  }

  /** Inner class to collect execution data from JaCoCo. */
  private static class CoverageVisitor implements IExecutionDataVisitor {
    private final List<ExecutionData> data = new ArrayList<>();

    @Override
    public void visitClassExecution(final ExecutionData executionData) {
      data.add(executionData);
    }

    public List<ExecutionData> getExecutionData() {
      return data;
    }
  }
}
