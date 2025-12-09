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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Aggregates validation results and produces reports.
 *
 * <p>Thread-safe for concurrent updates from multiple workers.
 *
 * <p>Provides both human-readable console output and machine-readable JSON reports for CI
 * integration.
 */
public class ValidationReport {

  private static final String REPORT_VERSION = "1.0";
  private static final ObjectMapper OBJECT_MAPPER =
      new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

  // Configuration
  private final String corpusDir;
  private final String fork;
  private final int workers;
  private final Instant startTime;

  // Statistics (thread-safe)
  private final AtomicInteger totalTests = new AtomicInteger(0);
  private final AtomicInteger passedTests = new AtomicInteger(0);
  private final AtomicInteger divergedTests = new AtomicInteger(0);
  private final AtomicInteger skippedTests = new AtomicInteger(0);
  private final AtomicInteger errorTests = new AtomicInteger(0);
  private final AtomicLong totalExecutionTimeMs = new AtomicLong(0);

  // Detailed results (synchronized access)
  private final List<ValidationResult> divergences =
      Collections.synchronizedList(new ArrayList<>());
  private final List<ValidationResult> errors = Collections.synchronizedList(new ArrayList<>());

  // Besu version
  private final String besuVersion;

  /**
   * Creates a new ValidationReport.
   *
   * @param corpusDir the corpus directory being validated
   * @param fork the EVM fork used for validation
   * @param workers the number of worker threads
   */
  public ValidationReport(final String corpusDir, final String fork, final int workers) {
    this.corpusDir = corpusDir;
    this.fork = fork;
    this.workers = workers;
    this.startTime = Instant.now();
    this.besuVersion = getDefaultBesuVersion();
  }

  private static String getDefaultBesuVersion() {
    Package pkg = ValidationReport.class.getPackage();
    if (pkg != null && pkg.getImplementationVersion() != null) {
      return pkg.getImplementationVersion();
    }
    return "dev";
  }

  /**
   * Records a validation result.
   *
   * @param result the validation result to record
   */
  public void recordResult(final ValidationResult result) {
    totalTests.incrementAndGet();

    if (result.getExecutionTime() != null) {
      totalExecutionTimeMs.addAndGet(result.getExecutionTime().toMillis());
    }

    switch (result.getStatus()) {
      case PASSED:
        passedTests.incrementAndGet();
        break;
      case DIVERGED:
        divergedTests.incrementAndGet();
        divergences.add(result);
        break;
      case SKIPPED:
        skippedTests.incrementAndGet();
        break;
      case ERROR:
        errorTests.incrementAndGet();
        errors.add(result);
        break;
    }
  }

  /** Returns the total number of tests processed. */
  public int getTotalTests() {
    return totalTests.get();
  }

  /** Returns the number of passed tests. */
  public int getPassedTests() {
    return passedTests.get();
  }

  /** Returns the number of diverged tests. */
  public int getDivergedTests() {
    return divergedTests.get();
  }

  /** Returns the number of skipped tests. */
  public int getSkippedTests() {
    return skippedTests.get();
  }

  /** Returns the number of errored tests. */
  public int getErrorTests() {
    return errorTests.get();
  }

  /** Returns the list of divergence results. */
  public List<ValidationResult> getDivergences() {
    return Collections.unmodifiableList(divergences);
  }

  /** Returns the list of error results. */
  public List<ValidationResult> getErrors() {
    return Collections.unmodifiableList(errors);
  }

  /** Returns the elapsed time since validation started. */
  public Duration getElapsedTime() {
    return Duration.between(startTime, Instant.now());
  }

  /** Returns the pass rate as a percentage. */
  public double getPassRate() {
    int validated = passedTests.get() + divergedTests.get();
    if (validated == 0) {
      return 100.0;
    }
    return 100.0 * passedTests.get() / validated;
  }

  /** Returns the average test execution time. */
  public Duration getAverageExecutionTime() {
    int executed = passedTests.get() + divergedTests.get() + errorTests.get();
    if (executed == 0) {
      return Duration.ZERO;
    }
    return Duration.ofMillis(totalExecutionTimeMs.get() / executed);
  }

  /** Returns true if any divergences were detected. */
  public boolean hasDivergences() {
    return divergedTests.get() > 0;
  }

  /** Returns true if any errors occurred. */
  public boolean hasErrors() {
    return errorTests.get() > 0;
  }

  /**
   * Returns a progress string for periodic updates.
   *
   * @return formatted progress string
   */
  public String getProgressString() {
    Duration elapsed = getElapsedTime();
    int total = totalTests.get();
    double rate = total / (elapsed.toMillis() / 1000.0 + 0.001);

    return String.format(
        "[%s] processed: %d (%.1f/s) | passed: %d | diverged: %d | skipped: %d | errors: %d",
        formatDuration(elapsed),
        total,
        rate,
        passedTests.get(),
        divergedTests.get(),
        skippedTests.get(),
        errorTests.get());
  }

  /** Prints the console summary report. */
  public void printConsoleSummary() {
    Duration elapsed = getElapsedTime();

    System.out.println();
    System.out.println("========================================");
    System.out.println("Cross-VM Corpus Validation Complete");
    System.out.println("========================================");
    System.out.println();
    System.out.printf("Corpus:     %s%n", corpusDir);
    System.out.printf("Fork:       %s%n", fork);
    System.out.printf("Workers:    %d%n", workers);
    System.out.printf("Duration:   %s%n", formatDuration(elapsed));
    System.out.println();
    System.out.println("Results:");
    System.out.printf("  Total:    %d%n", totalTests.get());
    System.out.printf("  Passed:   %d%n", passedTests.get());
    System.out.printf("  Diverged: %d%n", divergedTests.get());
    System.out.printf("  Skipped:  %d%n", skippedTests.get());
    System.out.printf("  Errors:   %d%n", errorTests.get());
    System.out.println();
    System.out.printf("Pass Rate:  %.1f%%%n", getPassRate());
    System.out.printf("Avg Time:   %s%n", formatDuration(getAverageExecutionTime()));
    System.out.println("========================================");

    if (hasDivergences()) {
      System.out.println();
      System.out.println("CONSENSUS DIVERGENCES DETECTED!");
      System.out.println();
      System.out.println("Diverged tests:");
      for (ValidationResult div : divergences) {
        System.out.printf("  %s%n", getFileName(div.getFilePath()));
        System.out.printf("    expected: %s%n", div.getExpectedTraceHash());
        System.out.printf("    actual:   %s%n", div.getActualTraceHash());
        if (!div.stateRootMatches()) {
          System.out.printf("    stateRoot mismatch!%n");
        }
      }
    }

    if (hasErrors()) {
      System.out.println();
      System.out.println("Errors:");
      for (ValidationResult err : errors) {
        System.out.printf("  %s: %s%n", getFileName(err.getFilePath()), err.getErrorMessage());
      }
    }
  }

  /**
   * Writes the JSON report to a file.
   *
   * @param outputFile the output file path
   * @throws IOException if writing fails
   */
  public void writeJsonReport(final File outputFile) throws IOException {
    ObjectNode report = createJsonReport();
    OBJECT_MAPPER.writeValue(outputFile, report);
  }

  /**
   * Writes the JSON report to a path.
   *
   * @param outputPath the output path
   * @throws IOException if writing fails
   */
  public void writeJsonReport(final Path outputPath) throws IOException {
    writeJsonReport(outputPath.toFile());
  }

  /**
   * Returns the JSON report as a string.
   *
   * @return JSON string
   */
  public String toJsonString() {
    try {
      return OBJECT_MAPPER.writeValueAsString(createJsonReport());
    } catch (IOException e) {
      return "{\"error\": \"Failed to generate JSON report\"}";
    }
  }

  private ObjectNode createJsonReport() {
    ObjectNode report = OBJECT_MAPPER.createObjectNode();

    // Metadata
    report.put("version", REPORT_VERSION);
    report.put("timestamp", Instant.now().toString());
    report.put("besuVersion", besuVersion);

    // Configuration
    ObjectNode config = OBJECT_MAPPER.createObjectNode();
    config.put("corpusDir", corpusDir);
    config.put("fork", fork);
    config.put("workers", workers);
    report.set("config", config);

    // Results summary
    ObjectNode results = OBJECT_MAPPER.createObjectNode();
    results.put("total", totalTests.get());
    results.put("passed", passedTests.get());
    results.put("diverged", divergedTests.get());
    results.put("skipped", skippedTests.get());
    results.put("errors", errorTests.get());
    results.put("passRate", getPassRate());
    results.put("durationMs", getElapsedTime().toMillis());
    results.put("avgExecutionMs", getAverageExecutionTime().toMillis());
    report.set("results", results);

    // Divergences
    if (!divergences.isEmpty()) {
      ArrayNode divArray = OBJECT_MAPPER.createArrayNode();
      for (ValidationResult div : divergences) {
        ObjectNode divNode = OBJECT_MAPPER.createObjectNode();
        divNode.put("path", div.getFilePath());
        if (div.getTestName() != null) {
          divNode.put("testName", div.getTestName());
        }
        divNode.put("sourceClient", div.getSourceClient());
        divNode.put("expectedTraceHash", div.getExpectedTraceHash());
        divNode.put("actualTraceHash", div.getActualTraceHash());
        if (div.getExpectedStateRoot() != null) {
          divNode.put("expectedStateRoot", div.getExpectedStateRoot());
        }
        if (div.getActualStateRoot() != null) {
          divNode.put("actualStateRoot", div.getActualStateRoot());
        }
        divNode.put("stateRootMatch", div.stateRootMatches());
        if (div.getExpectedTraceLines() != null) {
          divNode.put("expectedTraceLines", div.getExpectedTraceLines());
        }
        if (div.getActualTraceLines() != null) {
          divNode.put("actualTraceLines", div.getActualTraceLines());
        }
        divArray.add(divNode);
      }
      report.set("divergences", divArray);
    }

    // Errors
    if (!errors.isEmpty()) {
      ArrayNode errArray = OBJECT_MAPPER.createArrayNode();
      for (ValidationResult err : errors) {
        ObjectNode errNode = OBJECT_MAPPER.createObjectNode();
        errNode.put("path", err.getFilePath());
        errNode.put("error", err.getErrorMessage());
        errArray.add(errNode);
      }
      report.set("errors", errArray);
    }

    return report;
  }

  private String formatDuration(final Duration d) {
    if (d == null) {
      return "?";
    }
    long totalSeconds = d.getSeconds();
    long hours = totalSeconds / 3600;
    long minutes = (totalSeconds % 3600) / 60;
    long seconds = totalSeconds % 60;
    long millis = d.toMillisPart();

    if (hours > 0) {
      return String.format("%02d:%02d:%02d", hours, minutes, seconds);
    } else if (minutes > 0) {
      return String.format("%02d:%02d", minutes, seconds);
    } else if (seconds > 0) {
      return String.format("%d.%03ds", seconds, millis);
    } else {
      return String.format("%dms", millis);
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

  /**
   * Creates a DivergenceAnalyzer for this report and runs clustering analysis.
   *
   * @return the analyzer with completed analysis
   */
  public DivergenceAnalyzer analyzeAndCluster() {
    DivergenceAnalyzer analyzer = DivergenceAnalyzer.fromReport(this);
    analyzer.analyze();
    return analyzer;
  }

  /**
   * Prints a triage report that clusters divergences by likely root cause.
   *
   * <p>This is more useful than the raw divergence list when there are many divergences, as it
   * groups them into clusters that likely share the same bug, dramatically reducing the number of
   * distinct issues to investigate.
   */
  public void printTriageReport() {
    DivergenceAnalyzer analyzer = analyzeAndCluster();
    analyzer.printConsoleSummary();
  }

  /**
   * Returns the JSON triage report with clustering analysis.
   *
   * @return JSON string with clustering analysis
   */
  public String toTriageJsonString() {
    DivergenceAnalyzer analyzer = analyzeAndCluster();
    return analyzer.toJsonString();
  }
}
