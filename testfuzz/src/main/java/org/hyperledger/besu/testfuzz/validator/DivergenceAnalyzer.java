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
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Analyzes and clusters divergent test results to identify likely root causes.
 *
 * <p>This analyzer groups divergences by their (expectedTraceHash, actualTraceHash) signature,
 * which identifies tests that diverge in exactly the same way. This dramatically reduces the number
 * of distinct issues an analyst needs to investigate.
 *
 * <p>Example: 1,801 divergences might cluster into just 15-50 distinct signatures, representing
 * 15-50 likely distinct bugs rather than 1,801 separate issues.
 *
 * <p>The analyzer also:
 *
 * <ul>
 *   <li>Classifies clusters by divergence type (state root vs trace mismatch)
 *   <li>Detects common failure patterns from error messages
 *   <li>Ranks clusters by impact score for prioritized investigation
 *   <li>Selects representative examples from each cluster
 * </ul>
 */
public class DivergenceAnalyzer {

  private static final int DEFAULT_REPRESENTATIVES_PER_CLUSTER = 5;
  private static final ObjectMapper OBJECT_MAPPER =
      new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

  // Pattern matchers for failure classification
  private static final Pattern UNSUPPORTED_OPCODE_PATTERN =
      Pattern.compile("(?i)(unsupported|unknown|invalid).*(opcode|instruction)", Pattern.DOTALL);
  private static final Pattern GAS_PATTERN =
      Pattern.compile("(?i)(gas|out of gas|insufficient gas)", Pattern.DOTALL);
  private static final Pattern STACK_PATTERN =
      Pattern.compile("(?i)(stack|underflow|overflow)", Pattern.DOTALL);
  private static final Pattern MEMORY_PATTERN =
      Pattern.compile("(?i)(memory|mload|mstore)", Pattern.DOTALL);
  private static final Pattern JUMP_PATTERN =
      Pattern.compile("(?i)(jump|invalid jump|bad jump)", Pattern.DOTALL);
  private static final Pattern PRECOMPILE_PATTERN =
      Pattern.compile("(?i)(precompile|ecrecover|sha256|ripemd|identity|modexp|bn|blake)", Pattern.DOTALL);
  private static final Pattern CREATE_PATTERN =
      Pattern.compile("(?i)(create|create2|contract creation)", Pattern.DOTALL);
  private static final Pattern EOF_PATTERN = Pattern.compile("(?i)(eof|0xef)", Pattern.DOTALL);
  private static final Pattern PARSE_PATTERN =
      Pattern.compile("(?i)(parse|json|invalid format|malformed)", Pattern.DOTALL);
  private static final Pattern TX_CONSTRUCTION_PATTERN =
      Pattern.compile("(?i)(transaction.*null|null.*transaction|getTransaction.*null|invalid.*transaction)", Pattern.DOTALL);
  private static final Pattern BLOB_TX_PATTERN =
      Pattern.compile("(?i)(blob|versioned.*hash|type.*3|eip.?4844|kzg|commitment)", Pattern.DOTALL);

  private final List<ValidationResult> divergences;
  private final List<ValidationResult> errors;
  private final Map<String, DivergenceCluster> clustersBySignature;
  private List<DivergenceCluster> rankedClusters;

  /**
   * Creates a new analyzer for the given results.
   *
   * @param divergences list of divergent test results
   * @param errors list of error results
   */
  public DivergenceAnalyzer(
      final List<ValidationResult> divergences, final List<ValidationResult> errors) {
    this.divergences = new ArrayList<>(divergences);
    this.errors = new ArrayList<>(errors);
    this.clustersBySignature = new HashMap<>();
    this.rankedClusters = new ArrayList<>();
  }

  /**
   * Creates an analyzer from a validation report.
   *
   * @param report the validation report
   * @return new analyzer instance
   */
  public static DivergenceAnalyzer fromReport(final ValidationReport report) {
    return new DivergenceAnalyzer(report.getDivergences(), report.getErrors());
  }

  /** Performs the clustering analysis. */
  public void analyze() {
    // Step 1: Cluster divergences by signature
    clusterDivergences();

    // Step 2: Cluster errors separately
    clusterErrors();

    // Step 3: Detect failure patterns
    detectFailurePatterns();

    // Step 4: Select representatives for each cluster
    selectRepresentatives();

    // Step 5: Rank clusters by impact
    rankClusters();
  }

  /** Groups divergences by their (expected, actual) hash signature. */
  private void clusterDivergences() {
    for (ValidationResult result : divergences) {
      String signature = computeSignature(result);
      DivergenceCluster cluster =
          clustersBySignature.computeIfAbsent(
              signature,
              k -> new DivergenceCluster(result.getExpectedTraceHash(), result.getActualTraceHash()));
      cluster.addMember(result);
    }
  }

  /** Groups errors by their error message pattern. */
  private void clusterErrors() {
    // Group errors by normalized error message
    Map<String, List<ValidationResult>> errorGroups = new HashMap<>();
    for (ValidationResult error : errors) {
      String normalizedError = normalizeErrorMessage(error.getErrorMessage());
      errorGroups.computeIfAbsent(normalizedError, k -> new ArrayList<>()).add(error);
    }

    // Create clusters for each error group
    for (Map.Entry<String, List<ValidationResult>> entry : errorGroups.entrySet()) {
      String signature = "ERROR:" + entry.getKey();
      DivergenceCluster cluster = new DivergenceCluster("ERROR", entry.getKey());
      for (ValidationResult error : entry.getValue()) {
        cluster.addMember(error);
      }
      clustersBySignature.put(signature, cluster);
    }
  }

  /** Detects failure patterns for each cluster based on test characteristics and errors. */
  private void detectFailurePatterns() {
    for (DivergenceCluster cluster : clustersBySignature.values()) {
      DivergenceCluster.FailurePattern pattern = detectPattern(cluster);
      cluster.setFailurePattern(pattern);
    }
  }

  /** Selects representative examples for each cluster. */
  private void selectRepresentatives() {
    for (DivergenceCluster cluster : clustersBySignature.values()) {
      cluster.selectRepresentatives(DEFAULT_REPRESENTATIVES_PER_CLUSTER);
    }
  }

  /** Ranks clusters by impact score (descending). */
  private void rankClusters() {
    rankedClusters =
        clustersBySignature.values().stream()
            .sorted(Comparator.comparingDouble(DivergenceCluster::getImpactScore).reversed())
            .collect(Collectors.toList());
  }

  /**
   * Computes the signature for a validation result.
   *
   * @param result the result
   * @return signature string
   */
  private String computeSignature(final ValidationResult result) {
    String expected = result.getExpectedTraceHash() != null ? result.getExpectedTraceHash() : "null";
    String actual = result.getActualTraceHash() != null ? result.getActualTraceHash() : "null";
    return expected + ":" + actual;
  }

  /**
   * Normalizes an error message for grouping.
   *
   * @param errorMessage the original error message
   * @return normalized message
   */
  private String normalizeErrorMessage(final String errorMessage) {
    if (errorMessage == null) {
      return "unknown";
    }

    // Remove line numbers, addresses, and other variable content
    String normalized = errorMessage.toLowerCase(Locale.ROOT);
    normalized = normalized.replaceAll("0x[a-f0-9]+", "0x...");
    normalized = normalized.replaceAll("\\d+", "N");
    normalized = normalized.replaceAll("\\s+", " ");

    // Truncate to reasonable length
    if (normalized.length() > 100) {
      normalized = normalized.substring(0, 100);
    }

    return normalized.trim();
  }

  /**
   * Detects the failure pattern for a cluster.
   *
   * @param cluster the cluster to analyze
   * @return detected pattern
   */
  private DivergenceCluster.FailurePattern detectPattern(final DivergenceCluster cluster) {
    // First, check for transaction construction failure signature:
    // - Besu produces null/empty trace (actualTraceHash is null or actualTraceLines is 0)
    // - Geth produces output with traceLines=1 (just stateRoot)
    // - Test has expectException in name or is a known blob tx exception test
    if (isTxConstructionFailure(cluster)) {
      return DivergenceCluster.FailurePattern.TX_CONSTRUCTION_FAILURE;
    }

    // Check error messages
    for (ValidationResult member : cluster.getMembers()) {
      String error = member.getErrorMessage();
      if (error != null) {
        if (TX_CONSTRUCTION_PATTERN.matcher(error).find()) {
          return DivergenceCluster.FailurePattern.TX_CONSTRUCTION_FAILURE;
        }
        if (BLOB_TX_PATTERN.matcher(error).find()) {
          return DivergenceCluster.FailurePattern.BLOB_TX_ERROR;
        }
        if (UNSUPPORTED_OPCODE_PATTERN.matcher(error).find()) {
          return DivergenceCluster.FailurePattern.UNSUPPORTED_OPCODE;
        }
        if (GAS_PATTERN.matcher(error).find()) {
          return DivergenceCluster.FailurePattern.GAS_MISMATCH;
        }
        if (STACK_PATTERN.matcher(error).find()) {
          return DivergenceCluster.FailurePattern.STACK_ERROR;
        }
        if (MEMORY_PATTERN.matcher(error).find()) {
          return DivergenceCluster.FailurePattern.MEMORY_ERROR;
        }
        if (JUMP_PATTERN.matcher(error).find()) {
          return DivergenceCluster.FailurePattern.JUMP_ERROR;
        }
        if (PRECOMPILE_PATTERN.matcher(error).find()) {
          return DivergenceCluster.FailurePattern.PRECOMPILE_ERROR;
        }
        if (CREATE_PATTERN.matcher(error).find()) {
          return DivergenceCluster.FailurePattern.CREATE_ERROR;
        }
        if (EOF_PATTERN.matcher(error).find()) {
          return DivergenceCluster.FailurePattern.EOF_ERROR;
        }
        if (PARSE_PATTERN.matcher(error).find()) {
          return DivergenceCluster.FailurePattern.PARSE_ERROR;
        }
      }
    }

    // Check test name patterns
    for (String testName : cluster.getUniqueTestNames()) {
      String lower = testName.toLowerCase(Locale.ROOT);
      // Blob transaction patterns - check before general patterns
      if (lower.contains("blob") || lower.contains("eip4844") || lower.contains("type_3")
          || lower.contains("versioned_hash") || lower.contains("invalid_blob")) {
        return DivergenceCluster.FailurePattern.BLOB_TX_ERROR;
      }
      if (lower.contains("gas")) {
        return DivergenceCluster.FailurePattern.GAS_MISMATCH;
      }
      if (lower.contains("create")) {
        return DivergenceCluster.FailurePattern.CREATE_ERROR;
      }
      if (lower.contains("call")) {
        return DivergenceCluster.FailurePattern.CALL_DEPTH_ERROR;
      }
      if (lower.contains("precompile") || lower.contains("ecrecover") || lower.contains("modexp")) {
        return DivergenceCluster.FailurePattern.PRECOMPILE_ERROR;
      }
      if (lower.contains("eof")) {
        return DivergenceCluster.FailurePattern.EOF_ERROR;
      }
    }

    return DivergenceCluster.FailurePattern.UNKNOWN;
  }

  /**
   * Detects if a cluster represents a transaction construction failure.
   *
   * <p>This pattern occurs when:
   * <ul>
   *   <li>Besu's getTransaction() returns null due to invalid tx fields</li>
   *   <li>This causes dump-trace to produce no output (null actualTraceHash)</li>
   *   <li>While geth produces traceLines=1 (just the stateRoot line)</li>
   *   <li>Common for blob tx with invalid versioned hashes, malformed signatures, etc.</li>
   * </ul>
   *
   * <p>This is a known limitation in dump-trace, NOT a consensus bug.
   *
   * @param cluster the cluster to analyze
   * @return true if this appears to be a tx construction failure
   */
  private boolean isTxConstructionFailure(final DivergenceCluster cluster) {
    // Signature: actualTraceHash is null but expectedTraceHash exists
    if (cluster.getActualTraceHash() == null && cluster.getExpectedTraceHash() != null) {
      return true;
    }

    // Check if all members have null/zero actual trace lines but expected has 1 line
    // (geth outputs just stateRoot for tx construction failures)
    boolean allMembersHaveNoTrace = true;
    boolean anyMemberHasExpectedOneLine = false;

    for (ValidationResult member : cluster.getMembers()) {
      Integer actualLines = member.getActualTraceLines();
      Integer expectedLines = member.getExpectedTraceLines();

      if (actualLines != null && actualLines > 0) {
        allMembersHaveNoTrace = false;
      }
      if (expectedLines != null && expectedLines == 1) {
        anyMemberHasExpectedOneLine = true;
      }
    }

    if (allMembersHaveNoTrace && anyMemberHasExpectedOneLine) {
      return true;
    }

    // Check test names for blob tx exception patterns
    for (String testName : cluster.getUniqueTestNames()) {
      String lower = testName.toLowerCase(Locale.ROOT);
      if ((lower.contains("blob") || lower.contains("type_3") || lower.contains("eip4844"))
          && (lower.contains("invalid") || lower.contains("exception"))) {
        return true;
      }
    }

    return false;
  }

  /**
   * Returns the number of distinct clusters.
   *
   * @return cluster count
   */
  public int getClusterCount() {
    return clustersBySignature.size();
  }

  /**
   * Returns clusters ranked by impact score.
   *
   * @return ranked list of clusters
   */
  public List<DivergenceCluster> getRankedClusters() {
    return rankedClusters;
  }

  /**
   * Returns the top N clusters by impact.
   *
   * @param n maximum number of clusters
   * @return top clusters
   */
  public List<DivergenceCluster> getTopClusters(final int n) {
    return rankedClusters.stream().limit(n).collect(Collectors.toList());
  }

  /**
   * Returns clusters grouped by divergence type.
   *
   * @return map of type to clusters
   */
  public Map<DivergenceCluster.DivergenceType, List<DivergenceCluster>> getClustersByType() {
    return rankedClusters.stream()
        .collect(Collectors.groupingBy(DivergenceCluster::getDivergenceType));
  }

  /**
   * Returns clusters grouped by failure pattern.
   *
   * @return map of pattern to clusters
   */
  public Map<DivergenceCluster.FailurePattern, List<DivergenceCluster>> getClustersByPattern() {
    return rankedClusters.stream()
        .collect(Collectors.groupingBy(DivergenceCluster::getFailurePattern));
  }

  /** Prints a console summary of the clustering analysis. */
  public void printConsoleSummary() {
    System.out.println();
    System.out.println("========================================");
    System.out.println("Divergence Clustering Analysis");
    System.out.println("========================================");
    System.out.println();

    int totalDivergences = divergences.size() + errors.size();
    System.out.printf("Total divergences/errors: %d%n", totalDivergences);
    System.out.printf("Distinct clusters:        %d%n", clustersBySignature.size());
    System.out.printf(
        "Compression ratio:        %.1fx%n",
        totalDivergences > 0 ? (double) totalDivergences / clustersBySignature.size() : 1.0);
    System.out.println();

    // Summary by type
    Map<DivergenceCluster.DivergenceType, List<DivergenceCluster>> byType = getClustersByType();
    System.out.println("By Divergence Type:");
    for (DivergenceCluster.DivergenceType type : DivergenceCluster.DivergenceType.values()) {
      List<DivergenceCluster> typeClusters = byType.getOrDefault(type, List.of());
      if (!typeClusters.isEmpty()) {
        int memberCount = typeClusters.stream().mapToInt(DivergenceCluster::size).sum();
        System.out.printf(
            "  %-30s %3d clusters, %5d tests%n", type.name(), typeClusters.size(), memberCount);
      }
    }
    System.out.println();

    // Summary by pattern
    Map<DivergenceCluster.FailurePattern, List<DivergenceCluster>> byPattern = getClustersByPattern();
    System.out.println("By Failure Pattern:");
    for (DivergenceCluster.FailurePattern pattern : DivergenceCluster.FailurePattern.values()) {
      List<DivergenceCluster> patternClusters = byPattern.getOrDefault(pattern, List.of());
      if (!patternClusters.isEmpty()) {
        int memberCount = patternClusters.stream().mapToInt(DivergenceCluster::size).sum();
        String annotation = "";
        if (pattern == DivergenceCluster.FailurePattern.TX_CONSTRUCTION_FAILURE) {
          annotation = " [KNOWN LIMITATION]";
        } else if (pattern == DivergenceCluster.FailurePattern.BLOB_TX_ERROR) {
          annotation = " [CHECK TX VALIDITY]";
        }
        System.out.printf(
            "  %-30s %3d clusters, %5d tests%s%n",
            pattern.name(), patternClusters.size(), memberCount, annotation);
      }
    }
    System.out.println();

    // Add explanation for TX_CONSTRUCTION_FAILURE if present
    List<DivergenceCluster> txFailureClusters =
        byPattern.getOrDefault(DivergenceCluster.FailurePattern.TX_CONSTRUCTION_FAILURE, List.of());
    if (!txFailureClusters.isEmpty()) {
      int txFailureCount = txFailureClusters.stream().mapToInt(DivergenceCluster::size).sum();
      System.out.println("NOTE: TX_CONSTRUCTION_FAILURE divergences are a known limitation.");
      System.out.println("  These occur when transaction construction fails (e.g., invalid blob");
      System.out.println("  versioned hashes). Besu's getTransaction() returns null, producing no");
      System.out.println("  trace output, while geth outputs the pre-state root. This is NOT a");
      System.out.println("  consensus bug - both clients correctly reject the invalid transaction.");
      System.out.printf("  Affected tests: %d (can be safely ignored for consensus validation)%n", txFailureCount);
      System.out.println();
    }

    // Top clusters
    System.out.println("Top 10 Clusters (by impact):");
    System.out.println("----------------------------");
    List<DivergenceCluster> top = getTopClusters(10);
    for (int i = 0; i < top.size(); i++) {
      DivergenceCluster cluster = top.get(i);
      System.out.printf("%n#%d: %s%n", i + 1, cluster);
      System.out.printf("    Type: %s, Pattern: %s%n", cluster.getDivergenceType(), cluster.getFailurePattern());
      System.out.printf(
          "    State root mismatches: %d/%d%n",
          cluster.getStateRootMismatchCount(), cluster.size());

      // Show unique test name patterns
      if (!cluster.getUniqueTestNames().isEmpty()) {
        List<String> names = new ArrayList<>(cluster.getUniqueTestNames());
        String namePreview = names.stream().limit(3).collect(Collectors.joining(", "));
        if (names.size() > 3) {
          namePreview += " (+" + (names.size() - 3) + " more)";
        }
        System.out.printf("    Test patterns: %s%n", namePreview);
      }

      // Show representatives
      System.out.println("    Representatives:");
      for (ValidationResult rep : cluster.getRepresentatives()) {
        String fileName = getFileName(rep.getFilePath());
        System.out.printf("      - %s%n", fileName);
      }
    }
    System.out.println();
    System.out.println("========================================");
  }

  /**
   * Generates a JSON report of the clustering analysis.
   *
   * @return JSON string
   */
  public String toJsonString() {
    ObjectNode report = OBJECT_MAPPER.createObjectNode();

    // Summary
    ObjectNode summary = OBJECT_MAPPER.createObjectNode();
    summary.put("totalDivergences", divergences.size());
    summary.put("totalErrors", errors.size());
    summary.put("distinctClusters", clustersBySignature.size());
    summary.put(
        "compressionRatio",
        divergences.size() + errors.size() > 0
            ? (double) (divergences.size() + errors.size()) / clustersBySignature.size()
            : 1.0);
    report.set("summary", summary);

    // By type
    ObjectNode byType = OBJECT_MAPPER.createObjectNode();
    for (Map.Entry<DivergenceCluster.DivergenceType, List<DivergenceCluster>> entry :
        getClustersByType().entrySet()) {
      ObjectNode typeNode = OBJECT_MAPPER.createObjectNode();
      typeNode.put("clusters", entry.getValue().size());
      typeNode.put("tests", entry.getValue().stream().mapToInt(DivergenceCluster::size).sum());
      byType.set(entry.getKey().name(), typeNode);
    }
    report.set("byType", byType);

    // By pattern
    ObjectNode byPattern = OBJECT_MAPPER.createObjectNode();
    for (Map.Entry<DivergenceCluster.FailurePattern, List<DivergenceCluster>> entry :
        getClustersByPattern().entrySet()) {
      ObjectNode patternNode = OBJECT_MAPPER.createObjectNode();
      patternNode.put("clusters", entry.getValue().size());
      patternNode.put("tests", entry.getValue().stream().mapToInt(DivergenceCluster::size).sum());
      byPattern.set(entry.getKey().name(), patternNode);
    }
    report.set("byPattern", byPattern);

    // Clusters (ranked)
    ArrayNode clustersArray = OBJECT_MAPPER.createArrayNode();
    for (DivergenceCluster cluster : rankedClusters) {
      ObjectNode clusterNode = OBJECT_MAPPER.createObjectNode();
      clusterNode.put("signature", cluster.getSignature());
      clusterNode.put("expectedTraceHash", cluster.getExpectedTraceHash());
      clusterNode.put("actualTraceHash", cluster.getActualTraceHash());
      clusterNode.put("size", cluster.size());
      clusterNode.put("type", cluster.getDivergenceType().name());
      clusterNode.put("pattern", cluster.getFailurePattern().name());
      clusterNode.put("impactScore", cluster.getImpactScore());
      clusterNode.put("stateRootMismatches", cluster.getStateRootMismatchCount());

      // Test patterns
      ArrayNode testPatterns = OBJECT_MAPPER.createArrayNode();
      cluster.getUniqueTestNames().forEach(testPatterns::add);
      clusterNode.set("testPatterns", testPatterns);

      // Representatives
      ArrayNode reps = OBJECT_MAPPER.createArrayNode();
      for (ValidationResult rep : cluster.getRepresentatives()) {
        ObjectNode repNode = OBJECT_MAPPER.createObjectNode();
        repNode.put("path", rep.getFilePath());
        if (rep.getErrorMessage() != null) {
          repNode.put("error", rep.getErrorMessage());
        }
        reps.add(repNode);
      }
      clusterNode.set("representatives", reps);

      clustersArray.add(clusterNode);
    }
    report.set("clusters", clustersArray);

    try {
      return OBJECT_MAPPER.writeValueAsString(report);
    } catch (Exception e) {
      return "{\"error\": \"Failed to generate JSON\"}";
    }
  }

  private String getFileName(final String path) {
    if (path == null) {
      return "unknown";
    }
    int lastSlash = path.lastIndexOf('/');
    if (lastSlash >= 0 && lastSlash < path.length() - 1) {
      return path.substring(lastSlash + 1);
    }
    return path;
  }
}
