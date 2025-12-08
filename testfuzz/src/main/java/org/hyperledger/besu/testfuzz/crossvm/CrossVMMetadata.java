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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Metadata embedded in corpus entries for cross-VM trace comparison. Following the EEST standard,
 * this metadata is stored in the "_info" field INSIDE each test object (not at the top level).
 *
 * <p>Example (EEST-compliant format):
 *
 * <pre>{@code
 * {
 *   "testName": {
 *     "_info": {
 *       "comment": "Cross-VM consensus verification test",
 *       "generatedBy": "geth",
 *       "traceHash": "abc123def456...",
 *       "stateRoot": "0x...",
 *       "traceLines": 7,
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
 * @see <a href="https://github.com/ethereum/tests">ethereum-tests _info convention</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CrossVMMetadata {

  /** Current version of the cross-VM metadata specification. */
  public static final String CROSSVM_SPEC_VERSION = "1.0";

  // Required fields per CROSSVM_INFO_SPEC.md
  @JsonProperty("generatedBy")
  private String generatedBy;

  @JsonProperty("traceHash")
  private String traceHash;

  @JsonProperty("stateRoot")
  private String stateRoot;

  @JsonProperty("crossvmVersion")
  private String crossvmVersion;

  // Optional fields
  @JsonProperty("comment")
  private String comment;

  @JsonProperty("traceLines")
  private Integer traceLines;

  @JsonProperty("generatedAt")
  private String generatedAt;

  @JsonProperty("version")
  private String version;

  @JsonProperty("fork")
  private String fork;

  // Standard EEST fields (optional)
  @JsonProperty("fixture-format")
  private String fixtureFormat;

  @JsonProperty("filling-rpc-server")
  private String fillingRpcServer;

  @JsonProperty("source")
  private String source;

  @JsonProperty("sourceHash")
  private String sourceHash;

  /** Default constructor for Jackson. */
  public CrossVMMetadata() {}

  /**
   * Creates a new CrossVMMetadata with required fields per CROSSVM_INFO_SPEC.md.
   *
   * @param generatedBy the client that generated this (e.g., "geth", "besu")
   * @param traceHash the MD5 hash of normalized trace + stateRoot
   * @param stateRoot the post-execution state root
   * @param crossvmVersion the version of the cross-VM spec (use CROSSVM_SPEC_VERSION)
   */
  public CrossVMMetadata(
      final String generatedBy,
      final String traceHash,
      final String stateRoot,
      final String crossvmVersion) {
    this.generatedBy = generatedBy;
    this.traceHash = traceHash;
    this.stateRoot = stateRoot;
    this.crossvmVersion = crossvmVersion;
  }

  /**
   * Creates a new CrossVMMetadata with all common fields.
   *
   * @param generatedBy the client that generated this (e.g., "geth", "besu")
   * @param traceHash the MD5 hash of normalized trace + stateRoot
   * @param stateRoot the post-execution state root
   * @param traceLines the number of trace lines
   * @param version the client version
   */
  public CrossVMMetadata(
      final String generatedBy,
      final String traceHash,
      final String stateRoot,
      final int traceLines,
      final String version) {
    this.generatedBy = generatedBy;
    this.traceHash = traceHash;
    this.stateRoot = stateRoot;
    this.crossvmVersion = CROSSVM_SPEC_VERSION;
    this.traceLines = traceLines;
    this.version = version;
  }

  // ===== Required field getters =====

  /**
   * Gets the client that generated this metadata.
   *
   * @return the client name (e.g., "geth", "besu", "nethermind")
   */
  public String getGeneratedBy() {
    return generatedBy;
  }

  /**
   * Gets the trace hash.
   *
   * @return the MD5 hash of normalized trace + stateRoot
   */
  public String getTraceHash() {
    return traceHash;
  }

  /**
   * Gets the state root.
   *
   * @return the post-execution state root
   */
  public String getStateRoot() {
    return stateRoot;
  }

  /**
   * Gets the cross-VM specification version.
   *
   * @return the spec version (e.g., "1.0")
   */
  public String getCrossvmVersion() {
    return crossvmVersion;
  }

  // ===== Optional field getters =====

  /**
   * Gets the comment.
   *
   * @return the human-readable description
   */
  public String getComment() {
    return comment;
  }

  /**
   * Gets the number of trace lines.
   *
   * @return the trace line count, or null if not set
   */
  public Integer getTraceLines() {
    return traceLines;
  }

  /**
   * Gets the generation timestamp.
   *
   * @return ISO 8601 timestamp string
   */
  public String getGeneratedAt() {
    return generatedAt;
  }

  /**
   * Gets the client version.
   *
   * @return the version string
   */
  public String getVersion() {
    return version;
  }

  /**
   * Gets the fork name.
   *
   * @return the fork name (e.g., "Cancun", "Prague")
   */
  public String getFork() {
    return fork;
  }

  /**
   * Gets the fixture format.
   *
   * @return the fixture format (e.g., "state_test")
   */
  public String getFixtureFormat() {
    return fixtureFormat;
  }

  /**
   * Gets the filling RPC server.
   *
   * @return the client/version string that filled the test
   */
  public String getFillingRpcServer() {
    return fillingRpcServer;
  }

  /**
   * Gets the source file path.
   *
   * @return the path to the source file
   */
  public String getSource() {
    return source;
  }

  /**
   * Gets the source file hash.
   *
   * @return SHA256 hash of the source file
   */
  public String getSourceHash() {
    return sourceHash;
  }

  // ===== Setters for builder pattern =====

  /**
   * Sets the comment.
   *
   * @param comment the human-readable description
   * @return this metadata for chaining
   */
  public CrossVMMetadata setComment(final String comment) {
    this.comment = comment;
    return this;
  }

  /**
   * Sets the generation timestamp.
   *
   * @param generatedAt ISO 8601 timestamp
   * @return this metadata for chaining
   */
  public CrossVMMetadata setGeneratedAt(final String generatedAt) {
    this.generatedAt = generatedAt;
    return this;
  }

  /**
   * Sets the trace line count.
   *
   * @param traceLines the number of trace lines
   * @return this metadata for chaining
   */
  public CrossVMMetadata setTraceLines(final int traceLines) {
    this.traceLines = traceLines;
    return this;
  }

  /**
   * Sets the fork name.
   *
   * @param fork the fork name
   * @return this metadata for chaining
   */
  public CrossVMMetadata setFork(final String fork) {
    this.fork = fork;
    return this;
  }

  /**
   * Sets the fixture format.
   *
   * @param fixtureFormat the fixture format
   * @return this metadata for chaining
   */
  public CrossVMMetadata setFixtureFormat(final String fixtureFormat) {
    this.fixtureFormat = fixtureFormat;
    return this;
  }

  /**
   * Sets the filling RPC server.
   *
   * @param fillingRpcServer the client/version string
   * @return this metadata for chaining
   */
  public CrossVMMetadata setFillingRpcServer(final String fillingRpcServer) {
    this.fillingRpcServer = fillingRpcServer;
    return this;
  }

  // ===== Utility methods =====

  /**
   * Checks if this metadata was generated by a different client.
   *
   * @param thisClient the current client name (e.g., "besu")
   * @return true if generatedBy is set and differs from thisClient
   */
  public boolean isFromOtherClient(final String thisClient) {
    return generatedBy != null && !generatedBy.equalsIgnoreCase(thisClient);
  }

  /**
   * Checks if this metadata has a valid trace hash.
   *
   * @return true if traceHash is non-null and non-empty
   */
  public boolean hasTraceHash() {
    return traceHash != null && !traceHash.isEmpty();
  }

  /**
   * Checks if this metadata has all required fields per CROSSVM_INFO_SPEC.md.
   *
   * @return true if generatedBy, traceHash, stateRoot, and crossvmVersion are all set
   */
  public boolean hasRequiredFields() {
    return generatedBy != null
        && !generatedBy.isEmpty()
        && traceHash != null
        && !traceHash.isEmpty()
        && stateRoot != null
        && !stateRoot.isEmpty()
        && crossvmVersion != null
        && !crossvmVersion.isEmpty();
  }

  @Override
  public String toString() {
    return String.format(
        "CrossVMMetadata{generatedBy=%s, version=%s, traceHash=%s, stateRoot=%s, lines=%s, crossvmVersion=%s}",
        generatedBy,
        version,
        traceHash != null ? traceHash.substring(0, Math.min(8, traceHash.length())) : "null",
        stateRoot != null ? stateRoot.substring(0, Math.min(10, stateRoot.length())) : "null",
        traceLines != null ? traceLines : "null",
        crossvmVersion);
  }
}
