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

import java.util.Iterator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a corpus entry that may contain cross-VM metadata for consensus comparison.
 *
 * <p>This class handles parsing cross-VM metadata from state test JSON files, supporting both:
 *
 * <ul>
 *   <li><b>EEST format (preferred)</b>: "_info" field inside each test object
 *   <li><b>Legacy format</b>: "_crossvm" field at top level (for backwards compatibility)
 * </ul>
 *
 * <p>Example EEST format:
 *
 * <pre>{@code
 * {
 *   "testName": {
 *     "_info": {
 *       "generatedBy": "geth",
 *       "traceHash": "abc123...",
 *       "stateRoot": "0x...",
 *       "crossvmVersion": "1.0"
 *     },
 *     "env": { ... },
 *     "pre": { ... }
 *   }
 * }
 * }</pre>
 *
 * @see <a href="https://github.com/ethereum/tests">EEST _info convention</a>
 */
public class EnhancedCorpusEntry {

  private static final Logger LOG = LoggerFactory.getLogger(EnhancedCorpusEntry.class);

  /** EEST standard field name for metadata inside test objects. */
  public static final String INFO_FIELD = "_info";

  /** Legacy field name for top-level metadata (backwards compatibility). */
  public static final String LEGACY_CROSSVM_FIELD = "_crossvm";

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final byte[] testRaw;
  private final CrossVMMetadata metadata;
  private final String testName;
  private final boolean usesEestFormat;

  /**
   * Creates a new EnhancedCorpusEntry.
   *
   * @param testRaw the raw JSON bytes
   * @param metadata the parsed metadata (may be null)
   * @param testName the name of the first test in the file (may be null)
   * @param usesEestFormat true if metadata was found in EEST _info format
   */
  private EnhancedCorpusEntry(
      final byte[] testRaw,
      final CrossVMMetadata metadata,
      final String testName,
      final boolean usesEestFormat) {
    this.testRaw = testRaw;
    this.metadata = metadata;
    this.testName = testName;
    this.usesEestFormat = usesEestFormat;
  }

  /**
   * Parses a corpus entry from JSON bytes, extracting any cross-VM metadata. Supports both EEST
   * format (_info inside test) and legacy format (_crossvm at top level).
   *
   * @param json the raw JSON bytes
   * @return the enhanced corpus entry
   */
  public static EnhancedCorpusEntry parse(final byte[] json) {
    if (json == null || json.length == 0) {
      return new EnhancedCorpusEntry(json, null, null, false);
    }

    try {
      JsonNode root = OBJECT_MAPPER.readTree(json);
      CrossVMMetadata metadata = null;
      String testName = null;
      boolean usesEestFormat = false;

      // First, try EEST format: _info inside test objects
      if (root.isObject()) {
        Iterator<String> fieldNames = root.fieldNames();
        while (fieldNames.hasNext()) {
          String fieldName = fieldNames.next();
          // Skip the legacy _crossvm field
          if (LEGACY_CROSSVM_FIELD.equals(fieldName)) {
            continue;
          }
          JsonNode testNode = root.get(fieldName);
          if (testNode.isObject() && testNode.has(INFO_FIELD)) {
            JsonNode infoNode = testNode.get(INFO_FIELD);
            // Check if this _info has cross-VM metadata (has generatedBy field)
            if (infoNode.has("generatedBy") || infoNode.has("traceHash")) {
              metadata = OBJECT_MAPPER.treeToValue(infoNode, CrossVMMetadata.class);
              testName = fieldName;
              usesEestFormat = true;
              break; // Use metadata from first test found
            }
          }
        }
      }

      // Fallback to legacy format: _crossvm at top level
      if (metadata == null && root.has(LEGACY_CROSSVM_FIELD)) {
        JsonNode crossvmNode = root.get(LEGACY_CROSSVM_FIELD);
        metadata = OBJECT_MAPPER.treeToValue(crossvmNode, CrossVMMetadata.class);
        usesEestFormat = false;
      }

      return new EnhancedCorpusEntry(json, metadata, testName, usesEestFormat);
    } catch (Exception e) {
      LOG.debug("Failed to parse corpus entry for cross-VM metadata: {}", e.getMessage());
      return new EnhancedCorpusEntry(json, null, null, false);
    }
  }

  /**
   * Gets the raw test JSON bytes.
   *
   * @return the raw JSON
   */
  public byte[] getTestRaw() {
    return testRaw;
  }

  /**
   * Gets the cross-VM metadata (may be null).
   *
   * @return the metadata
   */
  public CrossVMMetadata getMetadata() {
    return metadata;
  }

  /**
   * Checks if this entry has cross-VM metadata from another client.
   *
   * @param thisClient the current client name (e.g., "besu")
   * @return true if metadata exists and is from a different client
   */
  public boolean shouldVerifyAgainst(final String thisClient) {
    return metadata != null && metadata.hasTraceHash() && metadata.isFromOtherClient(thisClient);
  }

  /**
   * Checks if this entry has any cross-VM metadata.
   *
   * @return true if metadata is present
   */
  public boolean hasMetadata() {
    return metadata != null;
  }

  /**
   * Returns the test JSON with cross-VM metadata fields removed. This removes both:
   *
   * <ul>
   *   <li>Legacy _crossvm field at top level
   *   <li>EEST _info field inside test objects (only cross-VM fields, preserving standard _info)
   * </ul>
   *
   * <p>Note: For EEST format, we don't remove the entire _info field since it may contain standard
   * EEST metadata. The test executor ignores unknown fields anyway.
   *
   * @return the JSON bytes suitable for test execution
   */
  public byte[] getTestWithoutMetadata() {
    if (metadata == null) {
      return testRaw; // No metadata to remove
    }

    try {
      JsonNode root = OBJECT_MAPPER.readTree(testRaw);
      if (!root.isObject()) {
        return testRaw;
      }

      ObjectNode rootObj = (ObjectNode) root;
      boolean modified = false;

      // Remove legacy _crossvm field if present
      if (rootObj.has(LEGACY_CROSSVM_FIELD)) {
        rootObj.remove(LEGACY_CROSSVM_FIELD);
        modified = true;
      }

      // For EEST format, the _info field is inside test objects.
      // We don't remove it since Besu's parser ignores unknown fields.
      // However, if strict compatibility is needed, we could strip cross-VM specific fields.

      if (modified) {
        return OBJECT_MAPPER.writeValueAsBytes(root);
      }
      return testRaw;
    } catch (Exception e) {
      LOG.debug("Failed to strip cross-VM metadata: {}", e.getMessage());
      return testRaw;
    }
  }

  /**
   * Gets the trace hash from metadata (if present).
   *
   * @return the trace hash or null
   */
  public String getTraceHash() {
    return metadata != null ? metadata.getTraceHash() : null;
  }

  /**
   * Gets the generating client name from metadata.
   *
   * @return the client name (e.g., "geth") or null
   */
  public String getGeneratedBy() {
    return metadata != null ? metadata.getGeneratedBy() : null;
  }

  /**
   * Gets the name of the test containing the metadata (for EEST format).
   *
   * @return the test name, or null if using legacy format or no metadata
   */
  public String getTestName() {
    return testName;
  }

  /**
   * Checks if this entry uses EEST format (_info inside test object).
   *
   * @return true if using EEST format, false if using legacy format or no metadata
   */
  public boolean usesEestFormat() {
    return usesEestFormat;
  }

  /**
   * Gets the fork name from metadata (if present).
   *
   * @return the fork name (e.g., "Prague") or null
   */
  public String getFork() {
    return metadata != null ? metadata.getFork() : null;
  }
}
