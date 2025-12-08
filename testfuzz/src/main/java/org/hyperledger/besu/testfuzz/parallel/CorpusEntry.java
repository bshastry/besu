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

import org.hyperledger.besu.crypto.MessageDigestFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A corpus entry with metadata for AFL-style energy scheduling.
 *
 * <p>Energy model (AFL-inspired):
 *
 * <ul>
 *   <li>Initial corpus entries start with energy=1
 *   <li>Entries discovering new coverage get energy boost
 *   <li>Energy decays with each mutation that doesn't find new coverage
 *   <li>High-energy entries are prioritized for mutation
 * </ul>
 */
public class CorpusEntry implements Comparable<CorpusEntry> {

  /** Initial energy for new corpus entries. */
  public static final int INITIAL_ENERGY = 1;

  /** Energy boost when new coverage is discovered. */
  public static final int NEW_COVERAGE_ENERGY_BOOST = 16;

  /** Maximum energy cap. */
  public static final int MAX_ENERGY = 64;

  /** Number of mutations before energy decay. */
  public static final int DECAY_THRESHOLD = 100;

  private final byte[] data;
  private final byte[] hash;
  private final long discoveryTime;
  private final int initialEdges;

  // Mutable state (thread-safe via AtomicInteger)
  private final AtomicInteger energy;
  private final AtomicInteger mutationCount;
  private final AtomicInteger childrenWithNewCoverage;
  private volatile long lastMutationTime;

  /**
   * Creates a new corpus entry.
   *
   * @param data the test data
   * @param initialEdges the edge count when this entry was discovered
   */
  public CorpusEntry(final byte[] data, final int initialEdges) {
    this.data = data.clone();
    this.hash = computeHash(data);
    this.discoveryTime = System.nanoTime();
    this.initialEdges = initialEdges;
    this.energy = new AtomicInteger(INITIAL_ENERGY);
    this.mutationCount = new AtomicInteger(0);
    this.childrenWithNewCoverage = new AtomicInteger(0);
    this.lastMutationTime = discoveryTime;
  }

  private static byte[] computeHash(final byte[] data) {
    try {
      MessageDigest md = MessageDigestFactory.create(MessageDigestFactory.SHA256_ALG);
      return md.digest(data);
    } catch (NoSuchAlgorithmException e) {
      // Fallback to simple hash
      int hashCode = Arrays.hashCode(data);
      return new byte[] {
        (byte) (hashCode >> 24), (byte) (hashCode >> 16), (byte) (hashCode >> 8), (byte) hashCode
      };
    }
  }

  /**
   * Priority comparison for the queue. Higher energy = higher priority (comes first in queue).
   * Tie-breaker: more recent discovery time.
   */
  @Override
  public int compareTo(final CorpusEntry other) {
    // Higher energy first
    int energyCompare = Integer.compare(other.energy.get(), this.energy.get());
    if (energyCompare != 0) {
      return energyCompare;
    }
    // More recent first (for same energy)
    return Long.compare(other.discoveryTime, this.discoveryTime);
  }

  /** Called when this entry is selected for mutation. */
  public void recordMutation() {
    int count = mutationCount.incrementAndGet();
    lastMutationTime = System.nanoTime();

    // Decay energy after threshold
    if (count > 0 && count % DECAY_THRESHOLD == 0 && energy.get() > 1) {
      energy.updateAndGet(e -> Math.max(1, e / 2));
    }
  }

  /** Called when a child mutation finds new coverage. */
  public void recordSuccessfulChild() {
    childrenWithNewCoverage.incrementAndGet();
    // Boost energy when producing good children
    energy.updateAndGet(e -> Math.min(MAX_ENERGY, e + NEW_COVERAGE_ENERGY_BOOST / 4));
  }

  /**
   * Creates a new entry derived from this one with coverage boost.
   *
   * @param mutatedData the mutated test data
   * @param parent the parent entry that was mutated
   * @param newEdges the number of new edges discovered
   * @return a new corpus entry with boosted energy
   */
  public static CorpusEntry createFromMutation(
      final byte[] mutatedData, final CorpusEntry parent, final int newEdges) {
    CorpusEntry child = new CorpusEntry(mutatedData, newEdges);
    child.energy.set(Math.min(MAX_ENERGY, INITIAL_ENERGY + (newEdges * NEW_COVERAGE_ENERGY_BOOST)));
    parent.recordSuccessfulChild();
    return child;
  }

  /**
   * Returns a copy of the data.
   *
   * @return copy of the test data
   */
  public byte[] getData() {
    return data.clone();
  }

  /**
   * Returns direct reference to data for performance (read-only!).
   *
   * @return direct reference to the test data
   */
  public byte[] getDataDirect() {
    return data;
  }

  /**
   * Returns the SHA-256 hash of the data.
   *
   * @return the hash
   */
  public byte[] getHash() {
    return hash;
  }

  /**
   * Returns the current energy level.
   *
   * @return the energy
   */
  public int getEnergy() {
    return energy.get();
  }

  /**
   * Returns the number of times this entry has been mutated.
   *
   * @return the mutation count
   */
  public int getMutationCount() {
    return mutationCount.get();
  }

  /**
   * Returns the discovery time in nanoseconds.
   *
   * @return the discovery time
   */
  public long getDiscoveryTime() {
    return discoveryTime;
  }

  /**
   * Returns the initial edge count when this entry was discovered.
   *
   * @return the initial edges
   */
  public int getInitialEdges() {
    return initialEdges;
  }

  /**
   * Returns the number of children that found new coverage.
   *
   * @return count of successful children
   */
  public int getChildrenWithNewCoverage() {
    return childrenWithNewCoverage.get();
  }

  /**
   * Returns the last mutation time in nanoseconds.
   *
   * @return the last mutation time
   */
  public long getLastMutationTime() {
    return lastMutationTime;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof CorpusEntry)) {
      return false;
    }
    return Arrays.equals(hash, ((CorpusEntry) o).hash);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(hash);
  }
}
