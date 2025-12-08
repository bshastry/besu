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

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/** Tests for EnhancedCorpusEntry parsing and cross-VM metadata extraction. */
class EnhancedCorpusEntryTest {

  private static final String SAMPLE_TEST_WITH_CROSSVM =
      """
      {
        "testName": {
          "env": { "currentCoinbase": "0x0000000000000000000000000000000000000000" },
          "pre": {},
          "transaction": { "data": ["0x"], "gasLimit": ["0x5208"], "value": ["0x0"] },
          "expect": [{ "indexes": { "data": 0 }, "network": [">=Prague"], "result": {} }]
        },
        "_crossvm": {
          "traceHash": "abc123def456789012345678901234567890",
          "stateRoot": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
          "traceLines": 42,
          "generatedBy": "geth",
          "version": "1.14.0-dev"
        }
      }
      """;

  private static final String SAMPLE_TEST_WITHOUT_CROSSVM =
      """
      {
        "testName": {
          "env": { "currentCoinbase": "0x0000000000000000000000000000000000000000" },
          "pre": {},
          "transaction": { "data": ["0x"], "gasLimit": ["0x5208"], "value": ["0x0"] }
        }
      }
      """;

  @Test
  void parse_withCrossVMMetadata_extractsMetadata() {
    byte[] json = SAMPLE_TEST_WITH_CROSSVM.getBytes(StandardCharsets.UTF_8);

    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(json);

    assertThat(entry.hasMetadata()).isTrue();
    assertThat(entry.getMetadata().getGeneratedBy()).isEqualTo("geth");
    assertThat(entry.getMetadata().getVersion()).isEqualTo("1.14.0-dev");
    assertThat(entry.getMetadata().getTraceHash())
        .isEqualTo("abc123def456789012345678901234567890");
    assertThat(entry.getMetadata().getStateRoot())
        .isEqualTo("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    assertThat(entry.getMetadata().getTraceLines()).isEqualTo(42);
  }

  @Test
  void parse_withoutCrossVMMetadata_noMetadata() {
    byte[] json = SAMPLE_TEST_WITHOUT_CROSSVM.getBytes(StandardCharsets.UTF_8);

    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(json);

    assertThat(entry.hasMetadata()).isFalse();
    assertThat(entry.getMetadata()).isNull();
  }

  @Test
  void parse_nullInput_noMetadata() {
    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(null);

    assertThat(entry.hasMetadata()).isFalse();
    assertThat(entry.getTestRaw()).isNull();
  }

  @Test
  void parse_emptyInput_noMetadata() {
    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(new byte[0]);

    assertThat(entry.hasMetadata()).isFalse();
  }

  @Test
  void parse_invalidJson_noMetadata() {
    byte[] invalidJson = "{ invalid json".getBytes(StandardCharsets.UTF_8);

    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(invalidJson);

    assertThat(entry.hasMetadata()).isFalse();
    assertThat(entry.getTestRaw()).isEqualTo(invalidJson);
  }

  @Test
  void shouldVerifyAgainst_fromOtherClient_true() {
    byte[] json = SAMPLE_TEST_WITH_CROSSVM.getBytes(StandardCharsets.UTF_8);
    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(json);

    // Besu should verify against geth-generated entries
    assertThat(entry.shouldVerifyAgainst("besu")).isTrue();
    // Geth should not verify against its own entries
    assertThat(entry.shouldVerifyAgainst("geth")).isFalse();
    // Case-insensitive
    assertThat(entry.shouldVerifyAgainst("GETH")).isFalse();
    assertThat(entry.shouldVerifyAgainst("Geth")).isFalse();
  }

  @Test
  void shouldVerifyAgainst_noMetadata_false() {
    byte[] json = SAMPLE_TEST_WITHOUT_CROSSVM.getBytes(StandardCharsets.UTF_8);
    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(json);

    assertThat(entry.shouldVerifyAgainst("besu")).isFalse();
  }

  @Test
  void getTestWithoutMetadata_removesCrossVMField() {
    byte[] json = SAMPLE_TEST_WITH_CROSSVM.getBytes(StandardCharsets.UTF_8);
    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(json);

    byte[] cleanTest = entry.getTestWithoutMetadata();
    String cleanJson = new String(cleanTest, StandardCharsets.UTF_8);

    // Should not contain _crossvm
    assertThat(cleanJson).doesNotContain("_crossvm");
    assertThat(cleanJson).doesNotContain("traceHash");
    assertThat(cleanJson).doesNotContain("generatedBy");
    // Should still contain the test content
    assertThat(cleanJson).contains("testName");
    assertThat(cleanJson).contains("currentCoinbase");
  }

  @Test
  void getTestWithoutMetadata_noMetadata_returnsSame() {
    byte[] json = SAMPLE_TEST_WITHOUT_CROSSVM.getBytes(StandardCharsets.UTF_8);
    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(json);

    byte[] cleanTest = entry.getTestWithoutMetadata();

    // Should return the same bytes
    assertThat(cleanTest).isEqualTo(json);
  }

  @Test
  void getTraceHash_withMetadata_returnsHash() {
    byte[] json = SAMPLE_TEST_WITH_CROSSVM.getBytes(StandardCharsets.UTF_8);
    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(json);

    assertThat(entry.getTraceHash()).isEqualTo("abc123def456789012345678901234567890");
  }

  @Test
  void getTraceHash_noMetadata_returnsNull() {
    byte[] json = SAMPLE_TEST_WITHOUT_CROSSVM.getBytes(StandardCharsets.UTF_8);
    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(json);

    assertThat(entry.getTraceHash()).isNull();
  }

  @Test
  void getGeneratedBy_withMetadata_returnsClient() {
    byte[] json = SAMPLE_TEST_WITH_CROSSVM.getBytes(StandardCharsets.UTF_8);
    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(json);

    assertThat(entry.getGeneratedBy()).isEqualTo("geth");
  }

  @Test
  void getGeneratedBy_noMetadata_returnsNull() {
    byte[] json = SAMPLE_TEST_WITHOUT_CROSSVM.getBytes(StandardCharsets.UTF_8);
    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(json);

    assertThat(entry.getGeneratedBy()).isNull();
  }

  @Test
  void crossVMMetadata_isFromOtherClient_variousCases() {
    CrossVMMetadata metadata = new CrossVMMetadata("hash", "root", 10, "geth", "1.0");

    assertThat(metadata.isFromOtherClient("besu")).isTrue();
    assertThat(metadata.isFromOtherClient("nethermind")).isTrue();
    assertThat(metadata.isFromOtherClient("geth")).isFalse();
    assertThat(metadata.isFromOtherClient("GETH")).isFalse();
    assertThat(metadata.isFromOtherClient("Geth")).isFalse();
  }

  @Test
  void crossVMMetadata_hasTraceHash_variousCases() {
    assertThat(new CrossVMMetadata("hash", "root", 10, "geth", "1.0").hasTraceHash()).isTrue();
    assertThat(new CrossVMMetadata("", "root", 10, "geth", "1.0").hasTraceHash()).isFalse();
    assertThat(new CrossVMMetadata(null, "root", 10, "geth", "1.0").hasTraceHash()).isFalse();
  }
}
