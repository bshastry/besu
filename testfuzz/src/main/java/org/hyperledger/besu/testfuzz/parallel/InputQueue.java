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

import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe priority queue for corpus entries with AFL-style energy scheduling.
 *
 * <p>Design:
 *
 * <ul>
 *   <li>PriorityBlockingQueue for concurrent access
 *   <li>ConcurrentHashMap for deduplication by content hash
 *   <li>Energy-based priority (higher energy = mutated sooner)
 * </ul>
 *
 * <p>Queue behavior:
 *
 * <ul>
 *   <li>poll(): Returns highest-energy entry, requeues after mutation
 *   <li>add(): Adds new entry if unique (by hash)
 *   <li>Re-queue entries after mutation to allow re-prioritization
 * </ul>
 */
public class InputQueue {

  private static final int DEFAULT_MAX_QUEUE_SIZE = 100_000;
  private static final int INITIAL_CAPACITY = 1000;

  private final PriorityBlockingQueue<CorpusEntry> queue;
  private final Set<ByteArrayWrapper> seenHashes;

  // Statistics
  private final AtomicLong totalAdded;
  private final AtomicLong duplicatesRejected;
  private final AtomicLong totalPolled;

  // Configuration
  private final int maxQueueSize;

  /** Creates an InputQueue with default max size. */
  public InputQueue() {
    this(DEFAULT_MAX_QUEUE_SIZE);
  }

  /**
   * Creates an InputQueue with specified max size.
   *
   * @param maxQueueSize maximum number of entries in the queue
   */
  public InputQueue(final int maxQueueSize) {
    this.maxQueueSize = maxQueueSize;
    this.queue = new PriorityBlockingQueue<>(INITIAL_CAPACITY);
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
  public boolean addInitial(final byte[] data, final int initialEdges) {
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
  public boolean addFromMutation(final byte[] data, final CorpusEntry parent, final int newEdges) {
    CorpusEntry entry = CorpusEntry.createFromMutation(data, parent, newEdges);
    return addEntry(entry);
  }

  private boolean addEntry(final CorpusEntry entry) {
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
   * Polls for the next entry to mutate. The entry is temporarily removed; caller must call
   * requeue() when done.
   *
   * @param timeout max time to wait
   * @param unit time unit
   * @return the entry, or null if timeout
   * @throws InterruptedException if interrupted while waiting
   */
  public CorpusEntry poll(final long timeout, final TimeUnit unit) throws InterruptedException {
    CorpusEntry entry = queue.poll(timeout, unit);
    if (entry != null) {
      totalPolled.incrementAndGet();
      entry.recordMutation();
    }
    return entry;
  }

  /**
   * Re-queues an entry after mutation (allows re-prioritization).
   *
   * @param entry the entry to requeue
   */
  public void requeue(final CorpusEntry entry) {
    queue.offer(entry);
  }

  /**
   * Gets current queue size.
   *
   * @return number of entries in queue
   */
  public int size() {
    return queue.size();
  }

  /**
   * Gets total unique entries seen.
   *
   * @return total unique entries
   */
  public int uniqueEntries() {
    return seenHashes.size();
  }

  /**
   * Gets statistics string.
   *
   * @return statistics
   */
  public String getStats() {
    return String.format(
        "queue=%d unique=%d added=%d dupes=%d polled=%d",
        queue.size(),
        seenHashes.size(),
        totalAdded.get(),
        duplicatesRejected.get(),
        totalPolled.get());
  }

  /**
   * Returns the total number of entries added.
   *
   * @return total added
   */
  public long getTotalAdded() {
    return totalAdded.get();
  }

  /**
   * Returns the total number of duplicates rejected.
   *
   * @return duplicates rejected
   */
  public long getDuplicatesRejected() {
    return duplicatesRejected.get();
  }

  /**
   * Returns the total number of entries polled.
   *
   * @return total polled
   */
  public long getTotalPolled() {
    return totalPolled.get();
  }

  /** Wrapper for byte[] to use as HashMap key. */
  private static class ByteArrayWrapper {
    private final byte[] data;
    private final int hashCode;

    ByteArrayWrapper(final byte[] data) {
      this.data = data;
      this.hashCode = Arrays.hashCode(data);
    }

    @Override
    public boolean equals(final Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof ByteArrayWrapper)) {
        return false;
      }
      return Arrays.equals(data, ((ByteArrayWrapper) o).data);
    }

    @Override
    public int hashCode() {
      return hashCode;
    }
  }
}
