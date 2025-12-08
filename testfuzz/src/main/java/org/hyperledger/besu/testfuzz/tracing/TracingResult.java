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
package org.hyperledger.besu.testfuzz.tracing;

/**
 * Contains the result of executing a state test with trace normalization. The trace hash is an MD5
 * hash of the normalized trace lines plus the state root, enabling cross-VM comparison.
 */
public class TracingResult {

  private final String traceHash; // MD5 hash (32 hex chars, lowercase)
  private final String stateRoot; // Post-execution state root (0x prefixed)
  private final int traceLines; // Number of trace lines processed

  /**
   * Creates a new TracingResult.
   *
   * @param traceHash the MD5 hash of normalized trace + stateRoot
   * @param stateRoot the post-execution state root
   * @param traceLines the number of trace lines processed
   */
  public TracingResult(final String traceHash, final String stateRoot, final int traceLines) {
    this.traceHash = traceHash;
    this.stateRoot = stateRoot;
    this.traceLines = traceLines;
  }

  /**
   * Gets the trace hash.
   *
   * @return the MD5 hash of normalized trace (32 hex chars, lowercase)
   */
  public String getTraceHash() {
    return traceHash;
  }

  /**
   * Gets the state root.
   *
   * @return the post-execution state root
   */
  public String getStateRoot() {
    return stateRoot;
  }

  /**
   * Gets the number of trace lines.
   *
   * @return the trace line count
   */
  public int getTraceLines() {
    return traceLines;
  }

  @Override
  public String toString() {
    return String.format(
        "TracingResult{hash=%s, stateRoot=%s, lines=%d}",
        traceHash != null ? traceHash.substring(0, Math.min(8, traceHash.length())) : "null",
        stateRoot != null ? stateRoot.substring(0, Math.min(10, stateRoot.length())) : "null",
        traceLines);
  }
}
