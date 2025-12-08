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

import org.hyperledger.besu.testfuzz.tracing.TracingResult;

import java.io.IOException;
import java.time.Instant;
import java.util.Iterator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Writes state test JSON files with embedded cross-VM metadata following the EEST standard.
 *
 * <p>The metadata is embedded in the "_info" field inside each test object, following the official
 * EEST/ethereum-tests convention. This ensures compatibility with all Ethereum clients.
 *
 * <p>Example output:
 *
 * <pre>{@code
 * {
 *   "testName": {
 *     "_info": {
 *       "comment": "Cross-VM consensus verification test",
 *       "generatedBy": "besu",
 *       "traceHash": "abc123...",
 *       "stateRoot": "0x...",
 *       "traceLines": 42,
 *       "crossvmVersion": "1.0",
 *       "generatedAt": "2025-12-08T12:00:00Z"
 *     },
 *     "env": { ... },
 *     "pre": { ... },
 *     "transaction": { ... },
 *     "post": { ... }
 *   }
 * }
 * }</pre>
 *
 * @see <a href="https://github.com/ethereum/tests">EEST _info convention</a>
 */
public class CrossVMMetadataWriter {

  private static final Logger LOG = LoggerFactory.getLogger(CrossVMMetadataWriter.class);
  private static final ObjectMapper OBJECT_MAPPER =
      new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

  private final String clientName;
  private final String clientVersion;

  /**
   * Creates a new CrossVMMetadataWriter.
   *
   * @param clientName the name of this client (e.g., "besu")
   * @param clientVersion the version of this client
   */
  public CrossVMMetadataWriter(final String clientName, final String clientVersion) {
    this.clientName = clientName;
    this.clientVersion = clientVersion;
  }

  /**
   * Embeds cross-VM metadata into a state test JSON using EEST _info format.
   *
   * @param testJson the original test JSON bytes
   * @param tracingResult the result from test execution with tracing
   * @param fork the fork name used for execution (optional)
   * @return the modified JSON bytes with embedded metadata
   * @throws IOException if JSON processing fails
   */
  public byte[] embedMetadata(
      final byte[] testJson, final TracingResult tracingResult, final String fork)
      throws IOException {
    JsonNode root = OBJECT_MAPPER.readTree(testJson);
    if (!root.isObject()) {
      LOG.warn("Cannot embed metadata: root is not an object");
      return testJson;
    }

    ObjectNode rootObj = (ObjectNode) root;

    // Remove legacy _crossvm field if present
    if (rootObj.has(EnhancedCorpusEntry.LEGACY_CROSSVM_FIELD)) {
      rootObj.remove(EnhancedCorpusEntry.LEGACY_CROSSVM_FIELD);
    }

    // Find the first test object and embed _info
    Iterator<String> fieldNames = rootObj.fieldNames();
    while (fieldNames.hasNext()) {
      String fieldName = fieldNames.next();
      JsonNode testNode = rootObj.get(fieldName);
      if (testNode.isObject()) {
        ObjectNode testObj = (ObjectNode) testNode;
        ObjectNode infoNode = createInfoNode(tracingResult, fork);
        testObj.set(EnhancedCorpusEntry.INFO_FIELD, infoNode);
        break; // Only embed in first test
      }
    }

    return OBJECT_MAPPER.writeValueAsBytes(root);
  }

  /**
   * Embeds cross-VM metadata into a state test JSON, preserving existing _info fields.
   *
   * @param testJson the original test JSON bytes
   * @param tracingResult the result from test execution with tracing
   * @param fork the fork name used for execution (optional)
   * @return the modified JSON bytes with embedded metadata
   * @throws IOException if JSON processing fails
   */
  public byte[] embedMetadataPreservingInfo(
      final byte[] testJson, final TracingResult tracingResult, final String fork)
      throws IOException {
    JsonNode root = OBJECT_MAPPER.readTree(testJson);
    if (!root.isObject()) {
      LOG.warn("Cannot embed metadata: root is not an object");
      return testJson;
    }

    ObjectNode rootObj = (ObjectNode) root;

    // Remove legacy _crossvm field if present
    if (rootObj.has(EnhancedCorpusEntry.LEGACY_CROSSVM_FIELD)) {
      rootObj.remove(EnhancedCorpusEntry.LEGACY_CROSSVM_FIELD);
    }

    // Find the first test object and merge into _info
    Iterator<String> fieldNames = rootObj.fieldNames();
    while (fieldNames.hasNext()) {
      String fieldName = fieldNames.next();
      JsonNode testNode = rootObj.get(fieldName);
      if (testNode.isObject()) {
        ObjectNode testObj = (ObjectNode) testNode;

        // Get existing _info or create new one
        ObjectNode infoNode;
        if (testObj.has(EnhancedCorpusEntry.INFO_FIELD)
            && testObj.get(EnhancedCorpusEntry.INFO_FIELD).isObject()) {
          infoNode = (ObjectNode) testObj.get(EnhancedCorpusEntry.INFO_FIELD);
        } else {
          infoNode = OBJECT_MAPPER.createObjectNode();
        }

        // Add cross-VM fields
        addCrossVMFields(infoNode, tracingResult, fork);
        testObj.set(EnhancedCorpusEntry.INFO_FIELD, infoNode);
        break; // Only embed in first test
      }
    }

    return OBJECT_MAPPER.writeValueAsBytes(root);
  }

  /**
   * Creates a new _info node with all cross-VM metadata fields.
   *
   * @param tracingResult the tracing result
   * @param fork the fork name (optional)
   * @return the _info ObjectNode
   */
  private ObjectNode createInfoNode(final TracingResult tracingResult, final String fork) {
    ObjectNode infoNode = OBJECT_MAPPER.createObjectNode();
    addCrossVMFields(infoNode, tracingResult, fork);
    return infoNode;
  }

  /**
   * Adds cross-VM metadata fields to an existing _info node.
   *
   * @param infoNode the _info node to modify
   * @param tracingResult the tracing result
   * @param fork the fork name (optional)
   */
  private void addCrossVMFields(
      final ObjectNode infoNode, final TracingResult tracingResult, final String fork) {

    // Required fields per CROSSVM_INFO_SPEC.md
    infoNode.put("generatedBy", clientName);
    infoNode.put("traceHash", tracingResult.getTraceHash());
    infoNode.put("stateRoot", tracingResult.getStateRoot());
    infoNode.put("crossvmVersion", CrossVMMetadata.CROSSVM_SPEC_VERSION);

    // Optional fields
    infoNode.put("comment", "Cross-VM consensus verification test");
    infoNode.put("traceLines", tracingResult.getTraceLines());
    infoNode.put("generatedAt", Instant.now().toString());
    infoNode.put("version", clientVersion);

    if (fork != null && !fork.isEmpty()) {
      infoNode.put("fork", fork);
    }

    // Standard EEST field
    infoNode.put("fixture-format", "state_test");
    infoNode.put("filling-rpc-server", clientName + "-" + clientVersion);
  }

  /**
   * Creates a CrossVMMetadata object from a tracing result.
   *
   * @param tracingResult the tracing result
   * @param fork the fork name (optional)
   * @return the metadata object
   */
  public CrossVMMetadata createMetadata(final TracingResult tracingResult, final String fork) {
    CrossVMMetadata metadata =
        new CrossVMMetadata(
            clientName,
            tracingResult.getTraceHash(),
            tracingResult.getStateRoot(),
            tracingResult.getTraceLines(),
            clientVersion);

    metadata
        .setComment("Cross-VM consensus verification test")
        .setGeneratedAt(Instant.now().toString())
        .setFixtureFormat("state_test")
        .setFillingRpcServer(clientName + "-" + clientVersion);

    if (fork != null && !fork.isEmpty()) {
      metadata.setFork(fork);
    }

    return metadata;
  }

  /**
   * Converts a test JSON from legacy _crossvm format to EEST _info format.
   *
   * @param testJson the original test JSON with legacy format
   * @return the converted JSON bytes with EEST format
   * @throws IOException if JSON processing fails
   */
  public byte[] convertLegacyToEest(final byte[] testJson) throws IOException {
    EnhancedCorpusEntry entry = EnhancedCorpusEntry.parse(testJson);
    if (!entry.hasMetadata() || entry.usesEestFormat()) {
      return testJson; // No conversion needed
    }

    JsonNode root = OBJECT_MAPPER.readTree(testJson);
    if (!root.isObject()) {
      return testJson;
    }

    ObjectNode rootObj = (ObjectNode) root;
    CrossVMMetadata metadata = entry.getMetadata();

    // Remove legacy _crossvm field
    if (rootObj.has(EnhancedCorpusEntry.LEGACY_CROSSVM_FIELD)) {
      rootObj.remove(EnhancedCorpusEntry.LEGACY_CROSSVM_FIELD);
    }

    // Find first test object and add _info
    Iterator<String> fieldNames = rootObj.fieldNames();
    while (fieldNames.hasNext()) {
      String fieldName = fieldNames.next();
      JsonNode testNode = rootObj.get(fieldName);
      if (testNode.isObject()) {
        ObjectNode testObj = (ObjectNode) testNode;
        ObjectNode infoNode = OBJECT_MAPPER.createObjectNode();

        // Copy metadata fields to _info
        if (metadata.getGeneratedBy() != null) {
          infoNode.put("generatedBy", metadata.getGeneratedBy());
        }
        if (metadata.getTraceHash() != null) {
          infoNode.put("traceHash", metadata.getTraceHash());
        }
        if (metadata.getStateRoot() != null) {
          infoNode.put("stateRoot", metadata.getStateRoot());
        }
        if (metadata.getTraceLines() != null) {
          infoNode.put("traceLines", metadata.getTraceLines());
        }
        if (metadata.getVersion() != null) {
          infoNode.put("version", metadata.getVersion());
        }
        // Add crossvmVersion if not already present
        infoNode.put(
            "crossvmVersion",
            metadata.getCrossvmVersion() != null
                ? metadata.getCrossvmVersion()
                : CrossVMMetadata.CROSSVM_SPEC_VERSION);

        testObj.set(EnhancedCorpusEntry.INFO_FIELD, infoNode);
        break;
      }
    }

    return OBJECT_MAPPER.writeValueAsBytes(root);
  }
}
