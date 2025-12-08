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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Thread-safe crash manager with deduplication. */
public class CrashManager {

  private static final Logger LOG = LoggerFactory.getLogger(CrashManager.class);

  private final File crashDir;
  private final Set<String> seenCrashHashes;
  private final AtomicLong totalCrashes;
  private final AtomicLong uniqueCrashes;

  /**
   * Creates a new CrashManager.
   *
   * @param crashDir directory to save crash files
   */
  public CrashManager(final File crashDir) {
    this.crashDir = crashDir;
    this.seenCrashHashes = ConcurrentHashMap.newKeySet();
    this.totalCrashes = new AtomicLong(0);
    this.uniqueCrashes = new AtomicLong(0);

    if (!crashDir.exists()) {
      crashDir.mkdirs();
    }
  }

  /**
   * Saves a crash, deduplicating by content hash.
   *
   * @param testData the test that caused the crash
   * @param error the error message
   * @param workerId the worker that found the crash
   * @return true if this is a unique crash
   */
  public boolean saveCrash(final byte[] testData, final String error, final int workerId) {
    totalCrashes.incrementAndGet();

    String hash = computeHash(testData);
    if (!seenCrashHashes.add(hash)) {
      return false; // Duplicate
    }

    uniqueCrashes.incrementAndGet();

    try {
      String filename =
          String.format(
              "crash-%s-w%d-%d.json", hash.substring(0, 16), workerId, System.currentTimeMillis());
      File crashFile = new File(crashDir, filename);

      try (FileOutputStream fos = new FileOutputStream(crashFile)) {
        fos.write(testData);
      }

      // Write metadata
      String metaFilename = filename.replace(".json", ".txt");
      File metaFile = new File(crashDir, metaFilename);
      try (FileOutputStream fos = new FileOutputStream(metaFile)) {
        String meta =
            String.format(
                "Crash at: %s%nWorker: %d%nError: %s%nHash: %s%n",
                Instant.now(), workerId, error != null ? error : "unknown", hash);
        fos.write(meta.getBytes(StandardCharsets.UTF_8));
      }

      LOG.info("[!] Unique crash saved: {}", filename);
      return true;

    } catch (IOException e) {
      LOG.error("Failed to save crash: {}", e.getMessage());
      return false;
    }
  }

  private String computeHash(final byte[] data) {
    try {
      MessageDigest md = MessageDigestFactory.create(MessageDigestFactory.SHA256_ALG);
      byte[] hash = md.digest(data);
      StringBuilder sb = new StringBuilder();
      for (byte b : hash) {
        sb.append(String.format("%02x", b));
      }
      return sb.toString();
    } catch (NoSuchAlgorithmException e) {
      return String.format("%08x", Arrays.hashCode(data));
    }
  }

  /**
   * Returns the total number of crashes detected.
   *
   * @return total crashes
   */
  public long getTotalCrashes() {
    return totalCrashes.get();
  }

  /**
   * Returns the number of unique crashes saved.
   *
   * @return unique crashes
   */
  public long getUniqueCrashes() {
    return uniqueCrashes.get();
  }

  /**
   * Gets statistics string.
   *
   * @return statistics
   */
  public String getStats() {
    return String.format("crashes: total=%d unique=%d", totalCrashes.get(), uniqueCrashes.get());
  }
}
