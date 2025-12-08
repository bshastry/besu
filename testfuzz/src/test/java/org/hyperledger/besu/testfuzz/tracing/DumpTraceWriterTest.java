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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import com.google.common.base.Splitter;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

/** Tests for DumpTraceWriter. */
class DumpTraceWriterTest {

  @Test
  void testWriteMeta() throws Exception {
    StringWriter sw = new StringWriter();
    try (DumpTraceWriter writer = new DumpTraceWriter(sw, false)) {
      writer.writeMeta("besu", "24.12.0", "Prague", "abc123", "TestName_d0g0v0");
    }

    String output = sw.toString();
    assertThat(output).contains("\"_meta\":");
    assertThat(output).contains("\"client\":\"besu\"");
    assertThat(output).contains("\"version\":\"24.12.0\"");
    assertThat(output).contains("\"fork\":\"Prague\"");
    assertThat(output).contains("\"inputHash\":\"abc123\"");
    assertThat(output).contains("\"testName\":\"TestName_d0g0v0\"");
    assertThat(output).contains("\"normalizerVersion\":\"1\"");
    assertThat(output).contains("\"timestamp\":");
  }

  @Test
  void testWriteTraceLine() throws Exception {
    StringWriter sw = new StringWriter();
    try (DumpTraceWriter writer = new DumpTraceWriter(sw, false)) {
      CanonicalOpLog log = new CanonicalOpLog();
      log.setDepth(1);
      log.setPc(0);
      log.setGas(100000000);
      log.setOp(0x60); // PUSH1
      log.setOpName("PUSH1");
      log.setStack(new ArrayList<>());

      writer.writeTraceLine(log);
    }

    String output = sw.toString();
    assertThat(output).contains("\"depth\":1");
    assertThat(output).contains("\"pc\":0");
    assertThat(output).contains("\"gas\":100000000");
    assertThat(output).contains("\"op\":\"0x60\"");
    assertThat(output).contains("\"opName\":\"PUSH1\"");
    assertThat(output).contains("\"stack\":[]");
  }

  @Test
  void testWriteFilteredWhenDisabled() throws Exception {
    StringWriter sw = new StringWriter();
    try (DumpTraceWriter writer = new DumpTraceWriter(sw, false)) { // includeFiltered = false
      CanonicalOpLog log = new CanonicalOpLog();
      log.setDepth(0);
      log.setPc(0);
      log.setOp(0x60);
      log.setOpName("PUSH1");

      writer.writeFiltered(DumpTraceWriter.FilterReason.DEPTH_ZERO, log);
    }

    // Output should be empty since includeFiltered is false
    assertThat(sw.toString()).isEmpty();
  }

  @Test
  void testWriteFilteredWhenEnabled() throws Exception {
    StringWriter sw = new StringWriter();
    try (DumpTraceWriter writer = new DumpTraceWriter(sw, true)) { // includeFiltered = true
      CanonicalOpLog log = new CanonicalOpLog();
      log.setDepth(0);
      log.setPc(0);
      log.setOp(0x00);
      log.setOpName("STOP");

      writer.writeFiltered(DumpTraceWriter.FilterReason.STOP_OPCODE, log);
    }

    String output = sw.toString();
    assertThat(output).contains("\"_filtered\":");
    assertThat(output).contains("\"reason\":\"STOP_OPCODE\"");
    assertThat(output).contains("\"depth\":0");
    assertThat(output).contains("\"pc\":0");
    assertThat(output).contains("\"op\":\"0x00\"");
    assertThat(output).contains("\"opName\":\"STOP\"");
  }

  @Test
  void testWriteStateRoot() throws Exception {
    StringWriter sw = new StringWriter();
    try (DumpTraceWriter writer = new DumpTraceWriter(sw, false)) {
      writer.writeStateRoot("0x1234567890abcdef");
    }

    String output = sw.toString();
    assertThat(output).contains("\"stateRoot\":\"0x1234567890abcdef\"");
  }

  @Test
  void testWriteResult() throws Exception {
    StringWriter sw = new StringWriter();
    try (DumpTraceWriter writer = new DumpTraceWriter(sw, false)) {
      writer.writeResult("abcdef123456", 42);
    }

    String output = sw.toString();
    assertThat(output).contains("\"_result\":");
    assertThat(output).contains("\"traceHash\":\"abcdef123456\"");
    assertThat(output).contains("\"traceLines\":42");
  }

  @Test
  void testFullTraceWithNormalizer() throws Exception {
    StringWriter sw = new StringWriter();
    try (DumpTraceWriter dumpWriter = new DumpTraceWriter(sw, true)) {
      // Write metadata
      dumpWriter.writeMeta("besu", "24.12.0", "Prague", "inputhash123", "SimpleTest_d0g0v0");

      // Create normalizer with dump writer
      TraceNormalizer normalizer = new TraceNormalizer(dumpWriter);

      // Process some logs
      CanonicalOpLog log1 = new CanonicalOpLog();
      log1.setDepth(1);
      log1.setPc(0);
      log1.setGas(100000);
      log1.setOp(0x60); // PUSH1
      log1.setOpName("PUSH1");
      log1.setStack(new ArrayList<>());
      normalizer.processLog(log1);

      // Log with depth=0 should be filtered
      CanonicalOpLog filteredLog = new CanonicalOpLog();
      filteredLog.setDepth(0);
      filteredLog.setPc(0);
      filteredLog.setOp(0x60);
      filteredLog.setOpName("PUSH1");
      normalizer.processLog(filteredLog);

      CanonicalOpLog log2 = new CanonicalOpLog();
      log2.setDepth(1);
      log2.setPc(2);
      log2.setGas(99997);
      log2.setOp(0x01); // ADD
      log2.setOpName("ADD");
      List<Bytes> stack = new ArrayList<>();
      stack.add(Bytes.fromHexString("0x01"));
      log2.setStack(stack);
      normalizer.processLog(log2);

      // Finish with state root
      normalizer.finish("0xabcdef");
    }

    String output = sw.toString();
    List<String> lines = Splitter.on('\n').omitEmptyStrings().splitToList(output);

    // Should have:
    // 1. _meta line
    // 2. _filtered line for depth=0 (filtered entries are written immediately)
    // 3. PUSH1 trace line (normalized entries are buffered then written)
    // 4. ADD trace line
    // 5. stateRoot line
    // 6. _result line
    assertThat(lines.size()).isEqualTo(6);
    assertThat(lines.get(0)).contains("\"_meta\":");
    assertThat(lines.get(1)).contains("\"_filtered\":");
    assertThat(lines.get(1)).contains("DEPTH_ZERO");
    assertThat(lines.get(2)).contains("\"opName\":\"PUSH1\"");
    assertThat(lines.get(3)).contains("\"opName\":\"ADD\"");
    assertThat(lines.get(4)).contains("\"stateRoot\":\"0xabcdef\"");
    assertThat(lines.get(5)).contains("\"_result\":");
  }

  @Test
  void testAllFilterReasons() throws Exception {
    StringWriter sw = new StringWriter();
    try (DumpTraceWriter writer = new DumpTraceWriter(sw, true)) {
      CanonicalOpLog log = new CanonicalOpLog();
      log.setDepth(1);
      log.setPc(0);
      log.setOp(0x60);
      log.setOpName("PUSH1");

      writer.writeFiltered(DumpTraceWriter.FilterReason.STOP_OPCODE, log);
      writer.writeFiltered(DumpTraceWriter.FilterReason.DEPTH_ZERO, log);
      writer.writeFiltered(DumpTraceWriter.FilterReason.DUPLICATE, log);
    }

    String output = sw.toString();
    assertThat(output).contains("\"reason\":\"STOP_OPCODE\"");
    assertThat(output).contains("\"reason\":\"DEPTH_ZERO\"");
    assertThat(output).contains("\"reason\":\"DUPLICATE\"");
  }
}
