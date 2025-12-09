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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Represents a cluster of divergent test results that likely share the same root cause.
 *
 * <p>Divergences are clustered by their (expectedTraceHash, actualTraceHash) signature pair. Tests
 * with identical signatures are assumed to diverge for the same reason, allowing analysts to triage
 * many divergences by investigating a few representative examples.
 *
 * <p>Example: If 500 tests all have expectedHash=ABC and actualHash=XYZ, they form one cluster
 * representing a single likely bug, not 500 separate issues.
 */
public class DivergenceCluster {

  /** Categories of divergence based on what mismatched. */
  public enum DivergenceType {
    /** Both trace hash and state root differ - most severe. */
    STATE_ROOT_AND_TRACE_MISMATCH,
    /** State root differs but trace hashes match - state mutation issue. */
    STATE_ROOT_ONLY_MISMATCH,
    /** Trace hash differs but state roots match - execution path difference. */
    TRACE_ONLY_MISMATCH,
    /** Execution error occurred. */
    ERROR
  }

  /** Common failure patterns detected from error messages or test characteristics. */
  public enum FailurePattern {
    /** Unknown or unclassified pattern. */
    UNKNOWN,
    /** Unsupported opcode execution. */
    UNSUPPORTED_OPCODE,
    /** Gas calculation difference. */
    GAS_MISMATCH,
    /** Nonce handling difference. */
    NONCE_MISMATCH,
    /** Balance calculation difference. */
    BALANCE_MISMATCH,
    /** Storage slot difference. */
    STORAGE_MISMATCH,
    /** Stack underflow/overflow. */
    STACK_ERROR,
    /** Memory access error. */
    MEMORY_ERROR,
    /** Invalid jump destination. */
    JUMP_ERROR,
    /** Precompile execution difference. */
    PRECOMPILE_ERROR,
    /** Create/Create2 difference. */
    CREATE_ERROR,
    /** Call depth or recursion issue. */
    CALL_DEPTH_ERROR,
    /** EOF-related difference. */
    EOF_ERROR,
    /** Test parsing or format error. */
    PARSE_ERROR
  }

  // Cluster identity - the signature
  private final String expectedTraceHash;
  private final String actualTraceHash;

  // Classification
  private DivergenceType divergenceType;
  private FailurePattern failurePattern;

  // Members of this cluster
  private final List<ValidationResult> members;

  // Computed statistics
  private int stateRootMismatchCount;
  private final Set<String> uniqueExpectedStateRoots;
  private final Set<String> uniqueActualStateRoots;
  private final Set<String> uniqueTestNames;

  // Representative examples (selected for analyst review)
  private final List<ValidationResult> representatives;

  /**
   * Creates a new divergence cluster with the given signature.
   *
   * @param expectedTraceHash the expected trace hash (from source client)
   * @param actualTraceHash the actual trace hash (from Besu)
   */
  public DivergenceCluster(final String expectedTraceHash, final String actualTraceHash) {
    this.expectedTraceHash = expectedTraceHash;
    this.actualTraceHash = actualTraceHash;
    this.members = new ArrayList<>();
    this.representatives = new ArrayList<>();
    this.uniqueExpectedStateRoots = new HashSet<>();
    this.uniqueActualStateRoots = new HashSet<>();
    this.uniqueTestNames = new HashSet<>();
    this.divergenceType = DivergenceType.TRACE_ONLY_MISMATCH;
    this.failurePattern = FailurePattern.UNKNOWN;
  }

  /**
   * Adds a divergent result to this cluster.
   *
   * @param result the validation result to add
   */
  public void addMember(final ValidationResult result) {
    members.add(result);

    // Track state root statistics
    if (!result.stateRootMatches()) {
      stateRootMismatchCount++;
    }
    if (result.getExpectedStateRoot() != null) {
      uniqueExpectedStateRoots.add(result.getExpectedStateRoot());
    }
    if (result.getActualStateRoot() != null) {
      uniqueActualStateRoots.add(result.getActualStateRoot());
    }

    // Track test name patterns
    String testName = extractTestName(result.getFilePath());
    if (testName != null) {
      uniqueTestNames.add(testName);
    }

    // Update divergence type
    updateDivergenceType();
  }

  /**
   * Selects representative examples from this cluster for analyst review.
   *
   * <p>Selection strategy picks diverse examples:
   *
   * <ul>
   *   <li>First member (earliest discovered)
   *   <li>Member with state root mismatch (if any)
   *   <li>Member with most trace lines (complex case)
   *   <li>Member with fewest trace lines (simple case)
   *   <li>Random additional example (for diversity)
   * </ul>
   *
   * @param maxRepresentatives maximum number of representatives to select
   */
  public void selectRepresentatives(final int maxRepresentatives) {
    representatives.clear();

    if (members.isEmpty()) {
      return;
    }

    // Always include first member
    representatives.add(members.get(0));

    if (members.size() == 1 || maxRepresentatives <= 1) {
      return;
    }

    // Find member with state root mismatch
    for (ValidationResult r : members) {
      if (!r.stateRootMatches() && !representatives.contains(r)) {
        representatives.add(r);
        break;
      }
    }

    if (representatives.size() >= maxRepresentatives) {
      return;
    }

    // Find member with most trace lines (if available)
    members.stream()
        .filter(r -> r.getActualTraceLines() != null)
        .filter(r -> !representatives.contains(r))
        .max(Comparator.comparingInt(ValidationResult::getActualTraceLines))
        .ifPresent(representatives::add);

    if (representatives.size() >= maxRepresentatives) {
      return;
    }

    // Find member with fewest trace lines (if available)
    members.stream()
        .filter(r -> r.getActualTraceLines() != null)
        .filter(r -> !representatives.contains(r))
        .min(Comparator.comparingInt(ValidationResult::getActualTraceLines))
        .ifPresent(representatives::add);

    // Fill remaining slots with additional examples
    for (ValidationResult r : members) {
      if (representatives.size() >= maxRepresentatives) {
        break;
      }
      if (!representatives.contains(r)) {
        representatives.add(r);
      }
    }
  }

  /**
   * Computes the cluster signature (unique identifier).
   *
   * @return the signature string
   */
  public String getSignature() {
    return expectedTraceHash + ":" + actualTraceHash;
  }

  /**
   * Computes an impact score for ranking clusters.
   *
   * <p>Formula: severity_weight * 0.5 + size_weight * 0.3 + uniqueness_weight * 0.2
   *
   * @return impact score between 0 and 1
   */
  public double getImpactScore() {
    // Severity component (0.5 weight)
    double severityScore =
        switch (divergenceType) {
          case STATE_ROOT_AND_TRACE_MISMATCH -> 1.0;
          case STATE_ROOT_ONLY_MISMATCH -> 0.8;
          case TRACE_ONLY_MISMATCH -> 0.5;
          case ERROR -> 0.9;
        };

    // Size component (0.3 weight) - logarithmic scale
    double sizeScore = Math.min(1.0, Math.log10(members.size() + 1) / 3.0);

    // Uniqueness component (0.2 weight) - more unique state roots = more complex
    double uniquenessScore =
        Math.min(1.0, (uniqueExpectedStateRoots.size() + uniqueActualStateRoots.size()) / 10.0);

    return severityScore * 0.5 + sizeScore * 0.3 + uniquenessScore * 0.2;
  }

  /** Updates the divergence type based on current members. */
  private void updateDivergenceType() {
    boolean hasStateRootMismatch = stateRootMismatchCount > 0;
    boolean hasTraceMismatch =
        expectedTraceHash != null
            && actualTraceHash != null
            && !expectedTraceHash.equals(actualTraceHash);

    // Check for errors
    boolean hasError = members.stream().anyMatch(ValidationResult::isError);

    if (hasError) {
      divergenceType = DivergenceType.ERROR;
    } else if (hasStateRootMismatch && hasTraceMismatch) {
      divergenceType = DivergenceType.STATE_ROOT_AND_TRACE_MISMATCH;
    } else if (hasStateRootMismatch) {
      divergenceType = DivergenceType.STATE_ROOT_ONLY_MISMATCH;
    } else {
      divergenceType = DivergenceType.TRACE_ONLY_MISMATCH;
    }
  }

  /**
   * Extracts a normalized test name from a file path.
   *
   * @param filePath the file path
   * @return the test name or null
   */
  private String extractTestName(final String filePath) {
    if (filePath == null) {
      return null;
    }
    int lastSlash = filePath.lastIndexOf('/');
    String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;

    // Remove .json extension
    if (fileName.endsWith(".json")) {
      fileName = fileName.substring(0, fileName.length() - 5);
    }

    // Extract base name (before _N suffix)
    int underscore = fileName.lastIndexOf('_');
    if (underscore > 0) {
      String suffix = fileName.substring(underscore + 1);
      // Check if suffix is numeric
      if (suffix.matches("\\d+")) {
        return fileName.substring(0, underscore);
      }
    }

    return fileName;
  }

  // Getters

  public String getExpectedTraceHash() {
    return expectedTraceHash;
  }

  public String getActualTraceHash() {
    return actualTraceHash;
  }

  public DivergenceType getDivergenceType() {
    return divergenceType;
  }

  public FailurePattern getFailurePattern() {
    return failurePattern;
  }

  public void setFailurePattern(final FailurePattern pattern) {
    this.failurePattern = pattern;
  }

  public List<ValidationResult> getMembers() {
    return members;
  }

  public int size() {
    return members.size();
  }

  public int getStateRootMismatchCount() {
    return stateRootMismatchCount;
  }

  public Set<String> getUniqueExpectedStateRoots() {
    return uniqueExpectedStateRoots;
  }

  public Set<String> getUniqueActualStateRoots() {
    return uniqueActualStateRoots;
  }

  public Set<String> getUniqueTestNames() {
    return uniqueTestNames;
  }

  public List<ValidationResult> getRepresentatives() {
    return representatives;
  }

  @Override
  public String toString() {
    return String.format(
        "Cluster[%s→%s] size=%d type=%s pattern=%s impact=%.2f",
        truncateHash(expectedTraceHash),
        truncateHash(actualTraceHash),
        members.size(),
        divergenceType,
        failurePattern,
        getImpactScore());
  }

  private String truncateHash(final String hash) {
    if (hash == null) {
      return "null";
    }
    return hash.length() > 8 ? hash.substring(0, 8) : hash;
  }
}
