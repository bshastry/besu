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

import org.hyperledger.besu.crypto.MessageDigestFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;

/**
 * Normalizes EVM traces to a canonical format for cross-VM comparison. This implementation matches
 * geth's normalizer.go exactly to produce identical MD5 hashes.
 *
 * <p>Key normalization rules:
 *
 * <ul>
 *   <li>Filter depth=0 entries (not real opcodes)
 *   <li>Filter STOP opcodes (op=0x00)
 *   <li>Skip duplicate lines with same (pc, depth, functionDepth)
 *   <li>Stack: last 6 items only, lowercase hex, minimal representation (no leading zeros)
 *   <li>Include stateRoot as final line before hash finalization
 * </ul>
 */
public class TraceNormalizer {

  private final MessageDigest md5;
  private int lineCount;
  private CanonicalOpLog prev; // For duplicate line detection

  /** Creates a new TraceNormalizer. */
  public TraceNormalizer() {
    try {
      this.md5 = MessageDigestFactory.create("MD5");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("MD5 algorithm not available", e);
    }
    this.lineCount = 0;
    this.prev = null;
  }

  /**
   * Process a single trace log entry. Applies filtering and writes normalized output to MD5 hasher.
   *
   * @param log the canonical op log entry
   */
  public void processLog(final CanonicalOpLog log) {
    // Filter 1: depth=0 means not a real opcode
    if (log.getDepth() == 0) {
      return;
    }

    // Filter 2: STOP opcodes (geth continues on virtual STOP at end of code)
    if (log.getOp() == 0x00) {
      return;
    }

    // Filter 3: Skip duplicate lines with same (pc, depth, functionDepth)
    if (prev != null
        && prev.getPc() == log.getPc()
        && prev.getDepth() == log.getDepth()
        && prev.getFunctionDepth() == log.getFunctionDepth()) {
      return; // Skip duplicate
    }

    // Write previous line (if any) and store current as new prev
    if (prev != null) {
      writeNormalized(prev);
    }
    prev = log;
  }

  /**
   * Finish processing and return the MD5 hash. This flushes any pending log entry and adds the
   * stateRoot as the final line.
   *
   * @param stateRoot the post-execution state root (0x prefixed hex)
   * @return the MD5 hash bytes
   */
  public byte[] finish(final String stateRoot) {
    // Flush pending log entry
    if (prev != null) {
      writeNormalized(prev);
      prev = null;
    }

    // Write stateRoot as final line: {"stateRoot":"0x..."}
    String rootLine = "{\"stateRoot\":\"" + stateRoot + "\"}";
    md5.update(rootLine.getBytes(StandardCharsets.UTF_8));
    md5.update((byte) '\n');
    lineCount++;

    return md5.digest();
  }

  /**
   * Gets the number of lines processed.
   *
   * @return the line count
   */
  public int getLineCount() {
    return lineCount;
  }

  /** Resets the normalizer for reuse. */
  public void reset() {
    md5.reset();
    lineCount = 0;
    prev = null;
  }

  /**
   * Writes a normalized log entry to the MD5 hasher.
   *
   * @param log the log entry
   */
  private void writeNormalized(final CanonicalOpLog log) {
    byte[] data = canonicalMarshal(log);
    md5.update(data);
    md5.update((byte) '\n');
    lineCount++;
  }

  /**
   * Produces deterministic JSON output for an oplog. Field order must match geth exactly: depth,
   * pc, [section], [functionDepth], gas, op, opName, stack
   *
   * @param log the log entry
   * @return the canonical JSON bytes
   */
  static byte[] canonicalMarshal(final CanonicalOpLog log) {
    StringBuilder b = new StringBuilder(256);

    // depth (always, decimal)
    b.append("{\"depth\":");
    b.append(log.getDepth());

    // pc (always, decimal)
    b.append(",\"pc\":");
    b.append(log.getPc());

    // section (only if non-zero, EOF)
    if (log.getSection() != 0) {
      b.append(",\"section\":");
      b.append(log.getSection());
    }

    // functionDepth (only if non-zero, EOF)
    if (log.getFunctionDepth() != 0) {
      b.append(",\"functionDepth\":");
      b.append(log.getFunctionDepth());
    }

    // gas (always, decimal)
    b.append(",\"gas\":");
    b.append(log.getGas());

    // op (hex, 0x-prefixed, 2 digits, zero-padded)
    b.append(",\"op\":\"0x");
    int op = log.getOp() & 0xFF;
    if (op < 0x10) {
      b.append('0');
    }
    b.append(Integer.toHexString(op));
    b.append('"');

    // opName (always)
    b.append(",\"opName\":\"");
    b.append(log.getOpName() != null ? log.getOpName() : "UNKNOWN");
    b.append('"');

    // stack (array of hex strings, last 6 items, lowercase, minimal representation)
    b.append(",\"stack\":[");
    List<Bytes> stack = log.getStack();
    if (stack != null && !stack.isEmpty()) {
      for (int i = 0; i < stack.size(); i++) {
        if (i > 0) {
          b.append(',');
        }
        b.append('"');
        b.append(formatStackItem(stack.get(i)));
        b.append('"');
      }
    }
    b.append(']');

    b.append('}');
    return b.toString().getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Formats a stack item as lowercase hex with minimal representation (no leading zeros). Must
   * match geth's uint256.Int.Hex() output exactly.
   *
   * <p>Examples: 0x0, 0xf, 0xff, 0xdeadbeef (not 0x00, 0x0f, 0x00ff)
   *
   * @param item the stack item (may be null)
   * @return the formatted hex string
   */
  static String formatStackItem(final Bytes item) {
    if (item == null || item.isEmpty()) {
      return "0x0";
    }

    // Find first non-zero byte
    int start = 0;
    while (start < item.size() && item.get(start) == 0) {
      start++;
    }

    if (start == item.size()) {
      return "0x0"; // All zeros
    }

    // Build hex string without leading zeros
    StringBuilder hex = new StringBuilder("0x");
    boolean firstByte = true;
    for (int i = start; i < item.size(); i++) {
      int b = item.get(i) & 0xFF;
      if (firstByte) {
        // First byte: don't pad with leading zero if < 0x10
        if (b < 0x10 && b > 0) {
          hex.append(Integer.toHexString(b));
        } else {
          hex.append(String.format("%02x", b));
        }
        firstByte = false;
      } else {
        // Subsequent bytes: always 2 digits
        hex.append(String.format("%02x", b));
      }
    }

    return hex.toString();
  }
}
