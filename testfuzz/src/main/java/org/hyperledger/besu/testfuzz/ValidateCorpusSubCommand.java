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
package org.hyperledger.besu.testfuzz;

import org.hyperledger.besu.testfuzz.validator.CorpusValidator;
import org.hyperledger.besu.testfuzz.validator.ValidationReport;
import org.hyperledger.besu.util.LogConfigurator;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * CLI subcommand for validating a cross-VM enhanced corpus against Besu's execution.
 *
 * <p>This tool takes a corpus directory produced by geth's statetest fuzzer (with embedded _info
 * metadata) and validates that Besu produces the same trace hashes.
 *
 * <p>Exit codes:
 *
 * <ul>
 *   <li>0: All tests passed
 *   <li>1: Divergences detected
 *   <li>2: Errors occurred (IO, parsing, etc.)
 * </ul>
 *
 * <p>Usage:
 *
 * <pre>
 * BesuFuzz validate-corpus --corpus-dir=/path/to/corpus
 * BesuFuzz validate-corpus --corpus-dir=/path/to/corpus --dump-traces --output-dir=./divergences
 * BesuFuzz validate-corpus --corpus-dir=/path/to/corpus --json --quiet
 * </pre>
 */
@Command(
    name = "validate-corpus",
    description = "Validate a cross-VM enhanced corpus against Besu's execution",
    mixinStandardHelpOptions = true)
public class ValidateCorpusSubCommand implements Runnable {

  @Option(
      names = {"--corpus-dir"},
      description = "Directory containing corpus files with cross-VM metadata",
      required = true)
  private File corpusDir;

  @Option(
      names = {"--fork"},
      description = "EVM fork to use for execution (default: Prague)",
      defaultValue = "Prague")
  private String fork;

  @Option(
      names = {"--workers", "-w"},
      description = "Number of worker threads (default: number of CPUs)",
      defaultValue = "0")
  private int workers;

  @Option(
      names = {"--dump-traces"},
      description = "Dump Besu traces for divergent tests (for debugging)")
  private boolean dumpTraces;

  @Option(
      names = {"--include-filtered"},
      description = "Include filtered entries (STOP, depth=0) in trace dumps")
  private boolean includeFiltered;

  @Option(
      names = {"--output-dir", "-o"},
      description = "Output directory for reports and trace dumps")
  private File outputDir;

  @Option(
      names = {"--json"},
      description = "Output machine-readable JSON report")
  private boolean jsonOutput;

  @Option(
      names = {"--quiet", "-q"},
      description = "Quiet mode (suppress progress, only show final result)")
  private boolean quiet;

  @Option(
      names = {"--triage"},
      description = "Enable triage mode: cluster divergences by likely root cause")
  private boolean triage;

  @Override
  public void run() {
    // Configure logging
    LogConfigurator.setLevel("", "OFF");

    // Resolve output directory
    File dumpDir = null;
    if (dumpTraces) {
      if (outputDir != null) {
        dumpDir = outputDir;
      } else {
        dumpDir = new File(corpusDir, "besu_traces");
      }
    }

    // Build validator
    CorpusValidator.Builder builder =
        new CorpusValidator.Builder()
            .corpusDir(corpusDir)
            .fork(fork)
            .workers(workers)
            .traceDumpDir(dumpDir)
            .includeFilteredInDump(includeFiltered)
            .quiet(quiet || jsonOutput);

    CorpusValidator validator = builder.build();

    try {
      // Run validation
      ValidationReport report = validator.validate();

      // Output JSON if requested
      if (jsonOutput) {
        if (triage) {
          System.out.println(report.toTriageJsonString());
        } else {
          System.out.println(report.toJsonString());
        }
      }

      // Print triage report if requested and not in JSON-only mode
      if (triage && !jsonOutput && !quiet) {
        report.printTriageReport();
      }

      // Write JSON report to file if output directory specified
      if (outputDir != null) {
        outputDir.mkdirs();
        Path reportPath = outputDir.toPath().resolve("validation_report.json");
        report.writeJsonReport(reportPath);

        if (!quiet && !jsonOutput) {
          System.out.println();
          System.out.println("Report saved to: " + reportPath);
        }
      }

      // Exit with appropriate code
      if (report.hasDivergences()) {
        System.exit(1);
      } else if (report.hasErrors()) {
        System.exit(2);
      } else {
        System.exit(0);
      }

    } catch (IOException e) {
      System.err.println("Error: " + e.getMessage());
      System.exit(2);
    }
  }
}
