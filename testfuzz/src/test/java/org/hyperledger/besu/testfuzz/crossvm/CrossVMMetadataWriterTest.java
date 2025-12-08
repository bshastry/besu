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

import org.hyperledger.besu.testfuzz.tracing.TracingResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Tests for CrossVMMetadataWriter - embedding EEST _info metadata into state tests. */
class CrossVMMetadataWriterTest {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
  private CrossVMMetadataWriter writer;

  private static final String SAMPLE_TEST =
      """
      {
        "testName": {
          "env": { "currentCoinbase": "0x0000000000000000000000000000000000000000" },
          "pre": {},
          "transaction": { "data": ["0x"], "gasLimit": ["0x5208"], "value": ["0x0"] }
        }
      }
      """;

  private static final String SAMPLE_TEST_WITH_LEGACY_CROSSVM =
      """
      {
        "testName": {
          "env": { "currentCoinbase": "0x0000000000000000000000000000000000000000" },
          "pre": {},
          "transaction": { "data": ["0x"], "gasLimit": ["0x5208"], "value": ["0x0"] }
        },
        "_crossvm": {
          "traceHash": "oldHash",
          "generatedBy": "geth"
        }
      }
      """;

  private static final String SAMPLE_TEST_WITH_EXISTING_INFO =
      """
      {
        "testName": {
          "_info": {
            "comment": "Original comment",
            "source": "test.py"
          },
          "env": { "currentCoinbase": "0x0000000000000000000000000000000000000000" },
          "pre": {},
          "transaction": { "data": ["0x"], "gasLimit": ["0x5208"], "value": ["0x0"] }
        }
      }
      """;

  @BeforeEach
  void setUp() {
    writer = new CrossVMMetadataWriter("besu", "24.12.0-SNAPSHOT");
  }

  @Test
  void embedMetadata_addsInfoFieldToTest() throws IOException {
    TracingResult result = new TracingResult("abc123hash", "0xstateRoot123", 10);
    byte[] testJson = SAMPLE_TEST.getBytes(StandardCharsets.UTF_8);

    byte[] resultJson = writer.embedMetadata(testJson, result, "Prague");
    JsonNode root = OBJECT_MAPPER.readTree(resultJson);

    // Verify _info was added inside the test object
    JsonNode infoNode = root.get("testName").get("_info");
    assertThat(infoNode).isNotNull();
    assertThat(infoNode.get("generatedBy").asText()).isEqualTo("besu");
    assertThat(infoNode.get("traceHash").asText()).isEqualTo("abc123hash");
    assertThat(infoNode.get("stateRoot").asText()).isEqualTo("0xstateRoot123");
    assertThat(infoNode.get("traceLines").asInt()).isEqualTo(10);
    assertThat(infoNode.get("crossvmVersion").asText()).isEqualTo("1.0");
    assertThat(infoNode.get("fork").asText()).isEqualTo("Prague");
    assertThat(infoNode.get("version").asText()).isEqualTo("24.12.0-SNAPSHOT");
    assertThat(infoNode.get("fixture-format").asText()).isEqualTo("state_test");
  }

  @Test
  void embedMetadata_removesLegacyCrossvmField() throws IOException {
    TracingResult result = new TracingResult("newHash", "0xnewRoot", 5);
    byte[] testJson = SAMPLE_TEST_WITH_LEGACY_CROSSVM.getBytes(StandardCharsets.UTF_8);

    byte[] resultJson = writer.embedMetadata(testJson, result, null);
    String resultStr = new String(resultJson, StandardCharsets.UTF_8);

    // Should not contain legacy _crossvm field
    assertThat(resultStr).doesNotContain("_crossvm");
    // Should contain new _info
    JsonNode root = OBJECT_MAPPER.readTree(resultJson);
    assertThat(root.get("testName").get("_info")).isNotNull();
  }

  @Test
  void embedMetadataPreservingInfo_mergesWithExistingInfo() throws IOException {
    TracingResult result = new TracingResult("newHash", "0xnewRoot", 5);
    byte[] testJson = SAMPLE_TEST_WITH_EXISTING_INFO.getBytes(StandardCharsets.UTF_8);

    byte[] resultJson = writer.embedMetadataPreservingInfo(testJson, result, "Prague");
    JsonNode root = OBJECT_MAPPER.readTree(resultJson);

    JsonNode infoNode = root.get("testName").get("_info");
    assertThat(infoNode).isNotNull();

    // Should have original fields preserved
    assertThat(infoNode.get("source").asText()).isEqualTo("test.py");

    // Should have new cross-VM fields added
    assertThat(infoNode.get("generatedBy").asText()).isEqualTo("besu");
    assertThat(infoNode.get("traceHash").asText()).isEqualTo("newHash");
    assertThat(infoNode.get("crossvmVersion").asText()).isEqualTo("1.0");

    // Comment is overwritten with the cross-VM comment
    assertThat(infoNode.get("comment").asText()).isEqualTo("Cross-VM consensus verification test");
  }

  @Test
  void embedMetadata_withoutFork_omitsForkField() throws IOException {
    TracingResult result = new TracingResult("hash", "root", 1);
    byte[] testJson = SAMPLE_TEST.getBytes(StandardCharsets.UTF_8);

    byte[] resultJson = writer.embedMetadata(testJson, result, null);
    JsonNode root = OBJECT_MAPPER.readTree(resultJson);

    JsonNode infoNode = root.get("testName").get("_info");
    assertThat(infoNode.has("fork")).isFalse();
  }

  @Test
  void createMetadata_createsValidMetadata() {
    TracingResult result = new TracingResult("traceHash123", "0xstateRoot", 42);

    CrossVMMetadata metadata = writer.createMetadata(result, "Prague");

    assertThat(metadata.getGeneratedBy()).isEqualTo("besu");
    assertThat(metadata.getTraceHash()).isEqualTo("traceHash123");
    assertThat(metadata.getStateRoot()).isEqualTo("0xstateRoot");
    assertThat(metadata.getTraceLines()).isEqualTo(42);
    assertThat(metadata.getCrossvmVersion()).isEqualTo("1.0");
    assertThat(metadata.getFork()).isEqualTo("Prague");
    assertThat(metadata.getVersion()).isEqualTo("24.12.0-SNAPSHOT");
    assertThat(metadata.hasRequiredFields()).isTrue();
  }

  @Test
  void convertLegacyToEest_convertsFormat() throws IOException {
    byte[] testJson = SAMPLE_TEST_WITH_LEGACY_CROSSVM.getBytes(StandardCharsets.UTF_8);

    byte[] resultJson = writer.convertLegacyToEest(testJson);
    String resultStr = new String(resultJson, StandardCharsets.UTF_8);

    // Should not contain legacy field
    assertThat(resultStr).doesNotContain("_crossvm");

    // Should have _info inside test object
    JsonNode root = OBJECT_MAPPER.readTree(resultJson);
    JsonNode infoNode = root.get("testName").get("_info");
    assertThat(infoNode).isNotNull();
    assertThat(infoNode.get("generatedBy").asText()).isEqualTo("geth");
    assertThat(infoNode.get("traceHash").asText()).isEqualTo("oldHash");
  }

  @Test
  void convertLegacyToEest_noopForEestFormat() throws IOException {
    String eestFormat =
        """
        {
          "testName": {
            "_info": {
              "generatedBy": "geth",
              "traceHash": "hash123"
            },
            "env": {}
          }
        }
        """;
    byte[] testJson = eestFormat.getBytes(StandardCharsets.UTF_8);

    byte[] resultJson = writer.convertLegacyToEest(testJson);

    // Should return same content (already EEST format)
    assertThat(resultJson).isEqualTo(testJson);
  }

  @Test
  void convertLegacyToEest_noopForNoMetadata() throws IOException {
    byte[] testJson = SAMPLE_TEST.getBytes(StandardCharsets.UTF_8);

    byte[] resultJson = writer.convertLegacyToEest(testJson);

    // Should return same content (no metadata to convert)
    assertThat(resultJson).isEqualTo(testJson);
  }

  @Test
  void resultingJson_canBeParsedByEnhancedCorpusEntry() throws IOException {
    TracingResult result = new TracingResult("hash123", "0xroot456", 15);
    byte[] testJson = SAMPLE_TEST.getBytes(StandardCharsets.UTF_8);

    byte[] resultJson = writer.embedMetadata(testJson, result, "Prague");

    // Verify the result can be parsed back
    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(resultJson);

    assertThat(entry.hasMetadata()).isTrue();
    assertThat(entry.usesEestFormat()).isTrue();
    assertThat(entry.getTestName()).isEqualTo("testName");
    assertThat(entry.getMetadata().getGeneratedBy()).isEqualTo("besu");
    assertThat(entry.getMetadata().getTraceHash()).isEqualTo("hash123");
    assertThat(entry.getMetadata().getStateRoot()).isEqualTo("0xroot456");
    assertThat(entry.getMetadata().getTraceLines()).isEqualTo(15);
    assertThat(entry.getFork()).isEqualTo("Prague");
  }
}
