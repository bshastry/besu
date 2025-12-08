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

import org.hyperledger.besu.testfuzz.tracing.CanonicalOpLog;
import org.hyperledger.besu.testfuzz.tracing.DumpTraceWriter;
import org.hyperledger.besu.testfuzz.tracing.TraceNormalizer;

import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.google.common.base.Splitter;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

/** Debug test to help diagnose trace normalization differences. */
class CrossVMDebugTest {

  @Test
  void testStackFormatting() {
    // Test various stack values to ensure format matches geth
    System.out.println("=== Stack Formatting Tests ===");

    // Test case 1: Simple value
    Bytes val1 = Bytes.fromHexString("0x01");
    System.out.println("0x01 -> " + TraceNormalizer.formatStackItem(val1));

    // Test case 2: Value < 0x10
    Bytes val2 = Bytes.fromHexString("0x0f");
    System.out.println("0x0f -> " + TraceNormalizer.formatStackItem(val2));

    // Test case 3: Value with leading zeros
    Bytes val3 = Bytes.fromHexString("0x00ff");
    System.out.println("0x00ff -> " + TraceNormalizer.formatStackItem(val3));

    // Test case 4: Zero
    Bytes val4 = Bytes.fromHexString("0x00");
    System.out.println("0x00 -> " + TraceNormalizer.formatStackItem(val4));

    // Test case 5: Full 32-byte word
    Bytes val5 =
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001");
    System.out.println("32-byte 1 -> " + TraceNormalizer.formatStackItem(val5));

    // Test case 6: Address-like value
    Bytes val6 = Bytes.fromHexString("0xcccccccccccccccccccccccccccccccccccccccc");
    System.out.println("address -> " + TraceNormalizer.formatStackItem(val6));
  }

  @Test
  void testCanonicalMarshal() {
    System.out.println("\n=== Canonical Marshal Tests ===");

    CanonicalOpLog log = new CanonicalOpLog();
    log.setDepth(1);
    log.setPc(0);
    log.setGas(100000000);
    log.setOp(0x60); // PUSH1
    log.setOpName("PUSH1");

    List<Bytes> stack = new ArrayList<>();
    stack.add(Bytes.fromHexString("0x01"));
    log.setStack(stack);

    byte[] marshaled = TraceNormalizer.canonicalMarshal(log);
    System.out.println("PUSH1 with stack [0x01]:");
    System.out.println(new String(marshaled, StandardCharsets.UTF_8));

    // Test with empty stack
    log.setStack(new ArrayList<>());
    marshaled = TraceNormalizer.canonicalMarshal(log);
    System.out.println("\nPUSH1 with empty stack:");
    System.out.println(new String(marshaled, StandardCharsets.UTF_8));

    // Test with STOP (should be filtered in normalizer)
    log.setOp(0x00);
    log.setOpName("STOP");
    marshaled = TraceNormalizer.canonicalMarshal(log);
    System.out.println("\nSTOP opcode:");
    System.out.println(new String(marshaled, StandardCharsets.UTF_8));
  }

  @Test
  void testFilteringRules() {
    System.out.println("\n=== Filtering Rules Tests ===");

    TraceNormalizer normalizer = new TraceNormalizer();

    // Create log with depth=0 (should be filtered)
    CanonicalOpLog log1 = new CanonicalOpLog();
    log1.setDepth(0);
    log1.setPc(0);
    log1.setGas(100000000);
    log1.setOp(0x60);
    log1.setOpName("PUSH1");
    log1.setStack(new ArrayList<>());

    normalizer.processLog(log1);
    normalizer.finish("0xabc123");
    System.out.println(
        "Depth=0 entry: line count = "
            + normalizer.getLineCount()
            + " (expect 1 for stateRoot only)");

    // Reset and test STOP filtering
    normalizer.reset();
    CanonicalOpLog log2 = new CanonicalOpLog();
    log2.setDepth(1);
    log2.setPc(0);
    log2.setGas(100000000);
    log2.setOp(0x00); // STOP
    log2.setOpName("STOP");
    log2.setStack(new ArrayList<>());

    normalizer.processLog(log2);
    normalizer.finish("0xabc123");
    System.out.println(
        "STOP opcode: line count = "
            + normalizer.getLineCount()
            + " (expect 1 for stateRoot only)");

    // Reset and test valid entry
    normalizer.reset();
    CanonicalOpLog log3 = new CanonicalOpLog();
    log3.setDepth(1);
    log3.setPc(0);
    log3.setGas(100000000);
    log3.setOp(0x60);
    log3.setOpName("PUSH1");
    log3.setStack(new ArrayList<>());

    normalizer.processLog(log3);
    normalizer.finish("0xabc123");
    System.out.println(
        "Valid PUSH1: line count = "
            + normalizer.getLineCount()
            + " (expect 2: 1 oplog + 1 stateRoot)");
  }

  @Test
  void testDumpTraceWriterIntegration() throws Exception {
    System.out.println("\n=== DumpTraceWriter Integration Test ===");

    StringWriter sw = new StringWriter();
    try (DumpTraceWriter dumpWriter = new DumpTraceWriter(sw, true)) {
      // Write metadata
      dumpWriter.writeMeta("besu", "24.12.0", "Prague", "abc123", "TestDump_d0g0v0");

      // Create normalizer with dump writer
      TraceNormalizer normalizer = new TraceNormalizer(dumpWriter);

      // Simulate a simple trace sequence
      CanonicalOpLog log1 = new CanonicalOpLog();
      log1.setDepth(1);
      log1.setPc(0);
      log1.setGas(100000000);
      log1.setOp(0x60); // PUSH1
      log1.setOpName("PUSH1");
      log1.setStack(new ArrayList<>());
      normalizer.processLog(log1);

      // This will be filtered (depth=0)
      CanonicalOpLog filteredLog = new CanonicalOpLog();
      filteredLog.setDepth(0);
      filteredLog.setPc(5);
      filteredLog.setOp(0x60);
      filteredLog.setOpName("PUSH1");
      normalizer.processLog(filteredLog);

      // STOP opcode (will be filtered)
      CanonicalOpLog stopLog = new CanonicalOpLog();
      stopLog.setDepth(1);
      stopLog.setPc(10);
      stopLog.setGas(99999000);
      stopLog.setOp(0x00);
      stopLog.setOpName("STOP");
      stopLog.setStack(new ArrayList<>());
      normalizer.processLog(stopLog);

      CanonicalOpLog log2 = new CanonicalOpLog();
      log2.setDepth(1);
      log2.setPc(2);
      log2.setGas(99999997);
      log2.setOp(0x01); // ADD
      log2.setOpName("ADD");
      List<Bytes> stack = new ArrayList<>();
      stack.add(Bytes.fromHexString("0x01"));
      stack.add(Bytes.fromHexString("0x02"));
      log2.setStack(stack);
      normalizer.processLog(log2);

      // Finish trace
      normalizer.finish("0xabcdef1234567890");
    }

    String output = sw.toString();
    System.out.println("Generated JSONL dump:");
    System.out.println("---");
    System.out.println(output);
    System.out.println("---");

    // Verify output structure
    List<String> lines = Splitter.on('\n').omitEmptyStrings().splitToList(output);
    System.out.println("\nLine count: " + lines.size());

    // Check for expected content
    boolean hasMeta = false;
    boolean hasFiltered = false;
    boolean hasStateRoot = false;
    boolean hasResult = false;
    int traceLines = 0;

    for (String line : lines) {
      if (line.contains("\"_meta\":")) {
        hasMeta = true;
      }
      if (line.contains("\"_filtered\":")) {
        hasFiltered = true;
        System.out.println("Filtered entry: " + line);
      }
      if (line.contains("\"stateRoot\":")) {
        hasStateRoot = true;
      }
      if (line.contains("\"_result\":")) {
        hasResult = true;
      }
      if (line.contains("\"depth\":")
          && !line.contains("\"_filtered\"")
          && !line.contains("\"_meta\"")) {
        traceLines++;
      }
    }

    System.out.println("\nVerification:");
    System.out.println("  Has _meta: " + hasMeta);
    System.out.println("  Has _filtered: " + hasFiltered);
    System.out.println("  Has stateRoot: " + hasStateRoot);
    System.out.println("  Has _result: " + hasResult);
    System.out.println("  Trace lines: " + traceLines);
  }
}
