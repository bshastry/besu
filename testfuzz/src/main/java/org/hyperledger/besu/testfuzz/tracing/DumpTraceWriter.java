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

import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Writes normalized trace lines to a JSONL file for cross-VM debugging. This interface enables
 * side-by-side comparison of traces between different EVM implementations.
 *
 * <p>Output format (JSONL):
 *
 * <pre>
 * {"_meta":{...}}
 * {"depth":1,"pc":0,"gas":100000000,"op":"0x60","opName":"PUSH1","stack":[]}
 * {"_filtered":{"reason":"STOP_OPCODE","depth":1,"pc":100,"op":"0x00","opName":"STOP"}}
 * {"stateRoot":"0x123..."}
 * {"_result":{"traceHash":"abc123...","traceLines":42,"finalLineHash":"xyz789..."}}
 * </pre>
 */
public class DumpTraceWriter implements Closeable {

  /** Filter reason codes for excluded trace entries. */
  public enum FilterReason {
    /** STOP opcode (0x00) filtered. */
    STOP_OPCODE,
    /** depth=0 entry filtered. */
    DEPTH_ZERO,
    /** Duplicate PC+depth+functionDepth entry filtered. */
    DUPLICATE
  }

  private final Writer writer;
  private final boolean includeFiltered;
  private String lastLineHash;

  /**
   * Creates a DumpTraceWriter that writes to a file.
   *
   * @param filePath the output file path
   * @param includeFiltered whether to include filtered entries
   * @throws IOException if file cannot be opened
   */
  public DumpTraceWriter(final String filePath, final boolean includeFiltered) throws IOException {
    this.writer = new BufferedWriter(new FileWriter(filePath, StandardCharsets.UTF_8));
    this.includeFiltered = includeFiltered;
    this.lastLineHash = null;
  }

  /**
   * Creates a DumpTraceWriter that writes to a provided Writer.
   *
   * @param writer the output writer
   * @param includeFiltered whether to include filtered entries
   */
  public DumpTraceWriter(final Writer writer, final boolean includeFiltered) {
    this.writer = writer;
    this.includeFiltered = includeFiltered;
    this.lastLineHash = null;
  }

  /**
   * Writes the metadata header line.
   *
   * @param client client name (e.g., "besu")
   * @param version client version
   * @param fork Ethereum fork name
   * @param inputHash MD5 hash of input test JSON
   * @param testName name of the specific subtest
   * @throws IOException if write fails
   */
  public void writeMeta(
      final String client,
      final String version,
      final String fork,
      final String inputHash,
      final String testName)
      throws IOException {
    StringBuilder sb = new StringBuilder();
    sb.append("{\"_meta\":{");
    sb.append("\"client\":\"").append(escapeJson(client)).append("\"");
    sb.append(",\"version\":\"").append(escapeJson(version)).append("\"");
    sb.append(",\"fork\":\"").append(escapeJson(fork)).append("\"");
    sb.append(",\"inputHash\":\"").append(escapeJson(inputHash)).append("\"");
    sb.append(",\"testName\":\"").append(escapeJson(testName)).append("\"");
    sb.append(",\"timestamp\":\"")
        .append(DateTimeFormatter.ISO_INSTANT.format(Instant.now()))
        .append("\"");
    sb.append(",\"normalizerVersion\":\"1\"");
    sb.append("}}");
    writer.write(sb.toString());
    writer.write('\n');
  }

  /**
   * Writes a normalized trace line.
   *
   * @param log the canonical op log entry
   * @throws IOException if write fails
   */
  public void writeTraceLine(final CanonicalOpLog log) throws IOException {
    byte[] data = TraceNormalizer.canonicalMarshal(log);
    String line = new String(data, StandardCharsets.UTF_8);
    writer.write(line);
    writer.write('\n');
    // Track last line hash for result footer
    lastLineHash = computeMD5(line);
  }

  /**
   * Writes a filtered entry (only if includeFiltered is true).
   *
   * @param reason the filter reason
   * @param log the filtered log entry
   * @throws IOException if write fails
   */
  public void writeFiltered(final FilterReason reason, final CanonicalOpLog log)
      throws IOException {
    if (!includeFiltered) {
      return;
    }

    StringBuilder sb = new StringBuilder();
    sb.append("{\"_filtered\":{");
    sb.append("\"reason\":\"").append(reason.name()).append("\"");
    sb.append(",\"depth\":").append(log.getDepth());
    sb.append(",\"pc\":").append(log.getPc());

    // op (hex, 0x-prefixed, 2 digits)
    sb.append(",\"op\":\"0x");
    int op = log.getOp() & 0xFF;
    if (op < 0x10) {
      sb.append('0');
    }
    sb.append(Integer.toHexString(op));
    sb.append("\"");

    sb.append(",\"opName\":\"").append(log.getOpName() != null ? log.getOpName() : "UNKNOWN");
    sb.append("\"}}");

    writer.write(sb.toString());
    writer.write('\n');
  }

  /**
   * Writes the state root line.
   *
   * @param stateRoot the post-execution state root (0x prefixed hex)
   * @throws IOException if write fails
   */
  public void writeStateRoot(final String stateRoot) throws IOException {
    String line = "{\"stateRoot\":\"" + stateRoot + "\"}";
    writer.write(line);
    writer.write('\n');
  }

  /**
   * Writes the result footer line.
   *
   * @param traceHash the MD5 hash of all trace lines
   * @param traceLines the number of trace lines
   * @throws IOException if write fails
   */
  public void writeResult(final String traceHash, final int traceLines) throws IOException {
    StringBuilder sb = new StringBuilder();
    sb.append("{\"_result\":{");
    sb.append("\"traceHash\":\"").append(traceHash).append("\"");
    sb.append(",\"traceLines\":").append(traceLines);
    if (lastLineHash != null) {
      sb.append(",\"finalLineHash\":\"").append(lastLineHash).append("\"");
    }
    sb.append("}}");
    writer.write(sb.toString());
    writer.write('\n');
  }

  @Override
  public void close() throws IOException {
    writer.close();
  }

  /**
   * Escapes a string for JSON output.
   *
   * @param s the input string
   * @return the escaped string
   */
  private static String escapeJson(final String s) {
    if (s == null) {
      return "";
    }
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"':
          sb.append("\\\"");
          break;
        case '\\':
          sb.append("\\\\");
          break;
        case '\n':
          sb.append("\\n");
          break;
        case '\r':
          sb.append("\\r");
          break;
        case '\t':
          sb.append("\\t");
          break;
        default:
          sb.append(c);
      }
    }
    return sb.toString();
  }

  /**
   * Computes MD5 hash of a string.
   *
   * @param s the input string
   * @return lowercase hex MD5 hash
   */
  private static String computeMD5(final String s) {
    try {
      java.security.MessageDigest md =
          org.hyperledger.besu.crypto.MessageDigestFactory.create("MD5");
      byte[] hash = md.digest(s.getBytes(StandardCharsets.UTF_8));
      StringBuilder hex = new StringBuilder();
      for (byte b : hash) {
        hex.append(String.format("%02x", b & 0xFF));
      }
      return hex.toString();
    } catch (java.security.NoSuchAlgorithmException e) {
      return "error";
    }
  }
}
