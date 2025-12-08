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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a corpus entry that may contain cross-VM metadata for consensus comparison. This class
 * handles parsing the "_crossvm" field from state test JSON.
 */
public class EnhancedCorpusEntry {

  private static final Logger LOG = LoggerFactory.getLogger(EnhancedCorpusEntry.class);
  private static final String CROSSVM_FIELD = "_crossvm";
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final byte[] testRaw;
  private final CrossVMMetadata metadata;

  /**
   * Creates a new EnhancedCorpusEntry.
   *
   * @param testRaw the raw JSON bytes
   * @param metadata the parsed metadata (may be null)
   */
  private EnhancedCorpusEntry(final byte[] testRaw, final CrossVMMetadata metadata) {
    this.testRaw = testRaw;
    this.metadata = metadata;
  }

  /**
   * Parses a corpus entry from JSON bytes, extracting any cross-VM metadata.
   *
   * @param json the raw JSON bytes
   * @return the enhanced corpus entry
   */
  public static EnhancedCorpusEntry parse(final byte[] json) {
    if (json == null || json.length == 0) {
      return new EnhancedCorpusEntry(json, null);
    }

    try {
      JsonNode root = OBJECT_MAPPER.readTree(json);
      CrossVMMetadata metadata = null;

      if (root.has(CROSSVM_FIELD)) {
        JsonNode crossvmNode = root.get(CROSSVM_FIELD);
        metadata = OBJECT_MAPPER.treeToValue(crossvmNode, CrossVMMetadata.class);
      }

      return new EnhancedCorpusEntry(json, metadata);
    } catch (Exception e) {
      LOG.debug("Failed to parse corpus entry for cross-VM metadata: {}", e.getMessage());
      return new EnhancedCorpusEntry(json, null);
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
   * Returns the test JSON with the _crossvm field removed. This is used when executing the test to
   * avoid the metadata being parsed as part of the test.
   *
   * @return the JSON bytes without _crossvm field
   */
  public byte[] getTestWithoutMetadata() {
    if (metadata == null) {
      return testRaw; // No metadata to remove
    }

    try {
      JsonNode root = OBJECT_MAPPER.readTree(testRaw);
      if (root.isObject() && root.has(CROSSVM_FIELD)) {
        ((ObjectNode) root).remove(CROSSVM_FIELD);
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
}
