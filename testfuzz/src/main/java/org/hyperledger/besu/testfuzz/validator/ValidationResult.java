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
package org.hyperledger.besu.testfuzz.validator;

import java.time.Duration;

/**
 * Result of validating a single corpus entry against Besu's execution.
 *
 * <p>Captures all relevant information for reporting and triage:
 *
 * <ul>
 *   <li>File path and test name
 *   <li>Expected vs actual trace hashes and state roots
 *   <li>Match/divergence status
 *   <li>Execution timing
 *   <li>Error information if execution failed
 * </ul>
 */
public class ValidationResult {

  /** Possible outcomes of validation. */
  public enum Status {
    /** Trace hashes matched - consensus agreement. */
    PASSED,
    /** Trace hashes differed - consensus divergence detected. */
    DIVERGED,
    /** Test was skipped (no metadata, invalid format, etc.). */
    SKIPPED,
    /** Execution error occurred. */
    ERROR
  }

  private final String filePath;
  private final String testName;
  private final Status status;
  private final String skipReason;

  // Source metadata (from corpus entry)
  private final String sourceClient;
  private final String sourceVersion;
  private final String expectedTraceHash;
  private final String expectedStateRoot;
  private final Integer expectedTraceLines;

  // Besu execution results
  private final String actualTraceHash;
  private final String actualStateRoot;
  private final Integer actualTraceLines;

  // Execution metadata
  private final Duration executionTime;
  private final String errorMessage;

  private ValidationResult(final Builder builder) {
    this.filePath = builder.filePath;
    this.testName = builder.testName;
    this.status = builder.status;
    this.skipReason = builder.skipReason;
    this.sourceClient = builder.sourceClient;
    this.sourceVersion = builder.sourceVersion;
    this.expectedTraceHash = builder.expectedTraceHash;
    this.expectedStateRoot = builder.expectedStateRoot;
    this.expectedTraceLines = builder.expectedTraceLines;
    this.actualTraceHash = builder.actualTraceHash;
    this.actualStateRoot = builder.actualStateRoot;
    this.actualTraceLines = builder.actualTraceLines;
    this.executionTime = builder.executionTime;
    this.errorMessage = builder.errorMessage;
  }

  /** Creates a builder for ValidationResult. */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Creates a PASSED result.
   *
   * @param filePath the file path
   * @param expectedHash the expected trace hash
   * @param actualHash the actual trace hash (should match)
   * @param duration the execution time
   * @return a PASSED ValidationResult
   */
  public static ValidationResult passed(
      final String filePath,
      final String expectedHash,
      final String actualHash,
      final Duration duration) {
    return builder()
        .filePath(filePath)
        .status(Status.PASSED)
        .expectedTraceHash(expectedHash)
        .actualTraceHash(actualHash)
        .executionTime(duration)
        .build();
  }

  /**
   * Creates a SKIPPED result.
   *
   * @param filePath the file path
   * @param reason the reason for skipping
   * @return a SKIPPED ValidationResult
   */
  public static ValidationResult skipped(final String filePath, final String reason) {
    return builder().filePath(filePath).status(Status.SKIPPED).skipReason(reason).build();
  }

  /**
   * Creates an ERROR result.
   *
   * @param filePath the file path
   * @param errorMessage the error message
   * @return an ERROR ValidationResult
   */
  public static ValidationResult error(final String filePath, final String errorMessage) {
    return builder().filePath(filePath).status(Status.ERROR).errorMessage(errorMessage).build();
  }

  // Getters

  public String getFilePath() {
    return filePath;
  }

  public String getTestName() {
    return testName;
  }

  public Status getStatus() {
    return status;
  }

  public String getSkipReason() {
    return skipReason;
  }

  public String getSourceClient() {
    return sourceClient;
  }

  public String getSourceVersion() {
    return sourceVersion;
  }

  public String getExpectedTraceHash() {
    return expectedTraceHash;
  }

  public String getExpectedStateRoot() {
    return expectedStateRoot;
  }

  public Integer getExpectedTraceLines() {
    return expectedTraceLines;
  }

  public String getActualTraceHash() {
    return actualTraceHash;
  }

  public String getActualStateRoot() {
    return actualStateRoot;
  }

  public Integer getActualTraceLines() {
    return actualTraceLines;
  }

  public Duration getExecutionTime() {
    return executionTime;
  }

  public String getErrorMessage() {
    return errorMessage;
  }

  /** Returns true if trace hashes matched. */
  public boolean isPassed() {
    return status == Status.PASSED;
  }

  /** Returns true if a consensus divergence was detected. */
  public boolean isDiverged() {
    return status == Status.DIVERGED;
  }

  /** Returns true if the test was skipped. */
  public boolean isSkipped() {
    return status == Status.SKIPPED;
  }

  /** Returns true if an error occurred. */
  public boolean isError() {
    return status == Status.ERROR;
  }

  /** Returns true if state roots also matched (when both are available). */
  public boolean stateRootMatches() {
    if (expectedStateRoot == null || actualStateRoot == null) {
      return true; // Cannot compare
    }
    return expectedStateRoot.equals(actualStateRoot);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append(status.name()).append(": ").append(filePath);

    switch (status) {
      case PASSED:
        sb.append(" (").append(formatDuration(executionTime)).append(")");
        break;
      case DIVERGED:
        sb.append("\n  expected: ").append(expectedTraceHash);
        sb.append("\n  actual:   ").append(actualTraceHash);
        if (!stateRootMatches()) {
          sb.append("\n  stateRoot expected: ").append(expectedStateRoot);
          sb.append("\n  stateRoot actual:   ").append(actualStateRoot);
        }
        break;
      case SKIPPED:
        sb.append(" (").append(skipReason).append(")");
        break;
      case ERROR:
        sb.append(" (").append(errorMessage).append(")");
        break;
    }

    return sb.toString();
  }

  private String formatDuration(final Duration d) {
    if (d == null) {
      return "?";
    }
    long ms = d.toMillis();
    if (ms < 1000) {
      return ms + "ms";
    }
    return String.format("%.2fs", ms / 1000.0);
  }

  /** Builder for ValidationResult. */
  public static class Builder {
    private String filePath;
    private String testName;
    private Status status;
    private String skipReason;
    private String sourceClient;
    private String sourceVersion;
    private String expectedTraceHash;
    private String expectedStateRoot;
    private Integer expectedTraceLines;
    private String actualTraceHash;
    private String actualStateRoot;
    private Integer actualTraceLines;
    private Duration executionTime;
    private String errorMessage;

    public Builder filePath(final String filePath) {
      this.filePath = filePath;
      return this;
    }

    public Builder testName(final String testName) {
      this.testName = testName;
      return this;
    }

    public Builder status(final Status status) {
      this.status = status;
      return this;
    }

    public Builder skipReason(final String skipReason) {
      this.skipReason = skipReason;
      return this;
    }

    public Builder sourceClient(final String sourceClient) {
      this.sourceClient = sourceClient;
      return this;
    }

    public Builder sourceVersion(final String sourceVersion) {
      this.sourceVersion = sourceVersion;
      return this;
    }

    public Builder expectedTraceHash(final String expectedTraceHash) {
      this.expectedTraceHash = expectedTraceHash;
      return this;
    }

    public Builder expectedStateRoot(final String expectedStateRoot) {
      this.expectedStateRoot = expectedStateRoot;
      return this;
    }

    public Builder expectedTraceLines(final Integer expectedTraceLines) {
      this.expectedTraceLines = expectedTraceLines;
      return this;
    }

    public Builder actualTraceHash(final String actualTraceHash) {
      this.actualTraceHash = actualTraceHash;
      return this;
    }

    public Builder actualStateRoot(final String actualStateRoot) {
      this.actualStateRoot = actualStateRoot;
      return this;
    }

    public Builder actualTraceLines(final Integer actualTraceLines) {
      this.actualTraceLines = actualTraceLines;
      return this;
    }

    public Builder executionTime(final Duration executionTime) {
      this.executionTime = executionTime;
      return this;
    }

    public Builder errorMessage(final String errorMessage) {
      this.errorMessage = errorMessage;
      return this;
    }

    public ValidationResult build() {
      return new ValidationResult(this);
    }
  }
}
