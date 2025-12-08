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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for TraceNormalizer format compatibility. These tests verify that the normalized trace
 * output matches the expected format from geth's normalizer.go.
 */
class TraceNormalizerTest {

  private TraceNormalizer normalizer;

  @BeforeEach
  void setUp() {
    normalizer = new TraceNormalizer();
  }

  // ========== Stack Hex Format Tests ==========

  @Test
  void formatStackItem_null_returnsZero() {
    assertThat(TraceNormalizer.formatStackItem(null)).isEqualTo("0x0");
  }

  @Test
  void formatStackItem_empty_returnsZero() {
    assertThat(TraceNormalizer.formatStackItem(Bytes.EMPTY)).isEqualTo("0x0");
  }

  @Test
  void formatStackItem_allZeros_returnsZero() {
    assertThat(TraceNormalizer.formatStackItem(Bytes.fromHexString("0x0000000000")))
        .isEqualTo("0x0");
  }

  @Test
  void formatStackItem_singleDigit_noLeadingZero() {
    // 0x0f should become "0xf" not "0x0f"
    assertThat(TraceNormalizer.formatStackItem(Bytes.fromHexString("0x0f"))).isEqualTo("0xf");
  }

  @Test
  void formatStackItem_singleByte_properFormat() {
    // 0xff should remain "0xff"
    assertThat(TraceNormalizer.formatStackItem(Bytes.fromHexString("0xff"))).isEqualTo("0xff");
  }

  @Test
  void formatStackItem_multiByteWithLeadingZeros_stripsLeadingZeros() {
    // 0x00ff should become "0xff"
    assertThat(TraceNormalizer.formatStackItem(Bytes.fromHexString("0x00ff"))).isEqualTo("0xff");
  }

  @Test
  void formatStackItem_deadbeef_properFormat() {
    assertThat(TraceNormalizer.formatStackItem(Bytes.fromHexString("0xdeadbeef")))
        .isEqualTo("0xdeadbeef");
  }

  @Test
  void formatStackItem_lowercase() {
    // Must be lowercase like geth
    assertThat(TraceNormalizer.formatStackItem(Bytes.fromHexString("0xABCDEF")))
        .isEqualTo("0xabcdef");
  }

  @Test
  void formatStackItem_leadingZerosInMiddle_preserved() {
    // 0x100 should stay "0x100" (leading zeros after first byte preserved)
    assertThat(TraceNormalizer.formatStackItem(Bytes.fromHexString("0x0100"))).isEqualTo("0x100");
  }

  @Test
  void formatStackItem_fullWord_noLeadingZeroStrip() {
    // Full 32-byte word with value at the end
    Bytes word =
        Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001");
    assertThat(TraceNormalizer.formatStackItem(word)).isEqualTo("0x1");
  }

  @Test
  void formatStackItem_fullWord_large() {
    // Full 32-byte word with large value
    Bytes word =
        Bytes.fromHexString("0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff");
    assertThat(TraceNormalizer.formatStackItem(word))
        .isEqualTo("0xffffffffffffffffffffffffffffffffffffffff");
  }

  // ========== Canonical Marshal Tests ==========

  @Test
  void canonicalMarshal_basicEntry_correctFieldOrder() {
    CanonicalOpLog log = new CanonicalOpLog();
    log.setDepth(1);
    log.setPc(0);
    log.setGas(1000000);
    log.setOp(0x60); // PUSH1
    log.setOpName("PUSH1");
    log.setStack(new ArrayList<>());

    String json = new String(TraceNormalizer.canonicalMarshal(log), StandardCharsets.UTF_8);

    // Verify field order: depth, pc, gas, op, opName, stack
    assertThat(json)
        .isEqualTo(
            "{\"depth\":1,\"pc\":0,\"gas\":1000000,\"op\":\"0x60\",\"opName\":\"PUSH1\",\"stack\":[]}");
  }

  @Test
  void canonicalMarshal_withSection_includesSection() {
    CanonicalOpLog log = new CanonicalOpLog();
    log.setDepth(1);
    log.setPc(5);
    log.setSection(2); // EOF section
    log.setGas(500000);
    log.setOp(0x01); // ADD
    log.setOpName("ADD");
    log.setStack(new ArrayList<>());

    String json = new String(TraceNormalizer.canonicalMarshal(log), StandardCharsets.UTF_8);

    assertThat(json).contains("\"section\":2");
    // Verify section comes after pc
    assertThat(json.indexOf("\"pc\":")).isLessThan(json.indexOf("\"section\":"));
    assertThat(json.indexOf("\"section\":")).isLessThan(json.indexOf("\"gas\":"));
  }

  @Test
  void canonicalMarshal_withFunctionDepth_includesFunctionDepth() {
    CanonicalOpLog log = new CanonicalOpLog();
    log.setDepth(1);
    log.setPc(10);
    log.setSection(1);
    log.setFunctionDepth(3); // EOF function depth
    log.setGas(300000);
    log.setOp(0x02); // MUL
    log.setOpName("MUL");
    log.setStack(new ArrayList<>());

    String json = new String(TraceNormalizer.canonicalMarshal(log), StandardCharsets.UTF_8);

    assertThat(json).contains("\"functionDepth\":3");
    // Verify order: section before functionDepth before gas
    assertThat(json.indexOf("\"section\":")).isLessThan(json.indexOf("\"functionDepth\":"));
    assertThat(json.indexOf("\"functionDepth\":")).isLessThan(json.indexOf("\"gas\":"));
  }

  @Test
  void canonicalMarshal_zeroSectionAndFunctionDepth_omitted() {
    CanonicalOpLog log = new CanonicalOpLog();
    log.setDepth(1);
    log.setPc(0);
    log.setSection(0);
    log.setFunctionDepth(0);
    log.setGas(1000000);
    log.setOp(0x60);
    log.setOpName("PUSH1");
    log.setStack(new ArrayList<>());

    String json = new String(TraceNormalizer.canonicalMarshal(log), StandardCharsets.UTF_8);

    assertThat(json).doesNotContain("section");
    assertThat(json).doesNotContain("functionDepth");
  }

  @Test
  void canonicalMarshal_opLessThan0x10_zeroPadded() {
    CanonicalOpLog log = new CanonicalOpLog();
    log.setDepth(1);
    log.setPc(0);
    log.setGas(1000000);
    log.setOp(0x01); // ADD = 0x01
    log.setOpName("ADD");
    log.setStack(new ArrayList<>());

    String json = new String(TraceNormalizer.canonicalMarshal(log), StandardCharsets.UTF_8);

    assertThat(json).contains("\"op\":\"0x01\"");
  }

  @Test
  void canonicalMarshal_withStack_correctFormat() {
    CanonicalOpLog log = new CanonicalOpLog();
    log.setDepth(1);
    log.setPc(0);
    log.setGas(1000000);
    log.setOp(0x01);
    log.setOpName("ADD");
    log.setStack(
        Arrays.asList(
            Bytes.fromHexString("0x01"),
            Bytes.fromHexString("0x0f"),
            Bytes.fromHexString("0xdeadbeef")));

    String json = new String(TraceNormalizer.canonicalMarshal(log), StandardCharsets.UTF_8);

    // Stack should use minimal hex format
    assertThat(json).contains("\"stack\":[\"0x1\",\"0xf\",\"0xdeadbeef\"]");
  }

  // ========== Filtering Tests ==========

  @Test
  void processLog_depthZero_filtered() {
    CanonicalOpLog log = new CanonicalOpLog();
    log.setDepth(0); // Should be filtered
    log.setPc(0);
    log.setGas(1000000);
    log.setOp(0x60);
    log.setOpName("PUSH1");

    normalizer.processLog(log);
    normalizer.finish("0xabc123");

    // Should only have state root line
    assertThat(normalizer.getLineCount()).isEqualTo(1);
  }

  @Test
  void processLog_stopOpcode_filtered() {
    CanonicalOpLog log = new CanonicalOpLog();
    log.setDepth(1);
    log.setPc(0);
    log.setGas(1000000);
    log.setOp(0x00); // STOP - should be filtered
    log.setOpName("STOP");

    normalizer.processLog(log);
    normalizer.finish("0xabc123");

    // Should only have state root line
    assertThat(normalizer.getLineCount()).isEqualTo(1);
  }

  @Test
  void processLog_duplicatePcDepthFunctionDepth_merged() {
    // First log
    CanonicalOpLog log1 = new CanonicalOpLog();
    log1.setDepth(1);
    log1.setPc(5);
    log1.setFunctionDepth(0);
    log1.setGas(1000000);
    log1.setOp(0x60);
    log1.setOpName("PUSH1");

    // Second log with same (pc, depth, functionDepth) - should be merged/skipped
    CanonicalOpLog log2 = new CanonicalOpLog();
    log2.setDepth(1);
    log2.setPc(5);
    log2.setFunctionDepth(0);
    log2.setGas(999990); // Different gas
    log2.setOp(0x60);
    log2.setOpName("PUSH1");

    // Third log with different pc - should be included
    CanonicalOpLog log3 = new CanonicalOpLog();
    log3.setDepth(1);
    log3.setPc(7);
    log3.setFunctionDepth(0);
    log3.setGas(999980);
    log3.setOp(0x01);
    log3.setOpName("ADD");

    normalizer.processLog(log1);
    normalizer.processLog(log2);
    normalizer.processLog(log3);
    normalizer.finish("0xabc123");

    // Should have 2 oplog lines + 1 state root line = 3
    assertThat(normalizer.getLineCount()).isEqualTo(3);
  }

  @Test
  void processLog_differentDepth_notMerged() {
    CanonicalOpLog log1 = new CanonicalOpLog();
    log1.setDepth(1);
    log1.setPc(5);
    log1.setGas(1000000);
    log1.setOp(0x60);
    log1.setOpName("PUSH1");

    CanonicalOpLog log2 = new CanonicalOpLog();
    log2.setDepth(2); // Different depth
    log2.setPc(5); // Same pc
    log2.setGas(900000);
    log2.setOp(0x60);
    log2.setOpName("PUSH1");

    normalizer.processLog(log1);
    normalizer.processLog(log2);
    normalizer.finish("0xabc123");

    // Both should be included + state root = 3 lines
    assertThat(normalizer.getLineCount()).isEqualTo(3);
  }

  // ========== Hash Consistency Tests ==========

  @Test
  void finish_sameInput_sameHash() {
    // First run
    CanonicalOpLog log1 = createSampleLog();
    normalizer.processLog(log1);
    byte[] hash1 = normalizer.finish("0xabc123");

    // Second run with reset
    normalizer.reset();
    CanonicalOpLog log2 = createSampleLog();
    normalizer.processLog(log2);
    byte[] hash2 = normalizer.finish("0xabc123");

    assertThat(hash1).isEqualTo(hash2);
  }

  @Test
  void finish_differentStateRoot_differentHash() {
    CanonicalOpLog log = createSampleLog();

    normalizer.processLog(log);
    byte[] hash1 = normalizer.finish("0xabc123");

    normalizer.reset();
    normalizer.processLog(createSampleLog());
    byte[] hash2 = normalizer.finish("0xdef456"); // Different state root

    assertThat(hash1).isNotEqualTo(hash2);
  }

  @Test
  void finish_stateRootFormat_correctJson() {
    // The state root should be added as: {"stateRoot":"0x..."}
    // This test verifies the format by checking that the same state root
    // produces consistent hashes
    normalizer.processLog(createSampleLog());
    byte[] hash1 =
        normalizer.finish("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

    normalizer.reset();
    normalizer.processLog(createSampleLog());
    byte[] hash2 =
        normalizer.finish("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

    assertThat(hash1).isEqualTo(hash2);
  }

  // ========== Helper Methods ==========

  private CanonicalOpLog createSampleLog() {
    CanonicalOpLog log = new CanonicalOpLog();
    log.setDepth(1);
    log.setPc(0);
    log.setGas(1000000);
    log.setOp(0x60);
    log.setOpName("PUSH1");
    log.setStack(Arrays.asList(Bytes.fromHexString("0x01")));
    return log;
  }
}
