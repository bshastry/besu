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

import org.hyperledger.besu.testfuzz.tracing.DumpTraceWriter;
import org.hyperledger.besu.util.LogConfigurator;

import java.io.File;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * CLI subcommand for dumping normalized traces for a single state test file.
 *
 * <p>This tool executes a state test and outputs the normalized trace in JSONL format, suitable
 * for side-by-side comparison with other EVM implementations (geth, nethermind, etc.).
 *
 * <p>Usage:
 *
 * <pre>
 * BesuFuzz dump-trace test.json
 * BesuFuzz dump-trace test.json -o trace.jsonl
 * BesuFuzz dump-trace test.json --include-filtered --fork=Osaka
 * </pre>
 */
@Command(
    name = "dump-trace",
    description = "Dump normalized trace for a single state test file",
    mixinStandardHelpOptions = true)
public class DumpTraceSubCommand implements Runnable {

  @Parameters(index = "0", description = "State test JSON file to process")
  private File testFile;

  @Option(
      names = {"-o", "--output"},
      description = "Output file path (default: stdout)")
  private File outputFile;

  @Option(
      names = {"--fork"},
      description = "EVM fork to use for execution (default: Prague)",
      defaultValue = "Prague")
  private String fork;

  @Option(
      names = {"--include-filtered"},
      description = "Include filtered entries (STOP opcodes, depth=0) in trace")
  private boolean includeFiltered;

  @Override
  public void run() {
    // Suppress logging
    LogConfigurator.setLevel("", "OFF");

    // Validate input
    if (!testFile.exists()) {
      System.err.println("Error: Test file not found: " + testFile.getAbsolutePath());
      System.exit(2);
    }

    if (!testFile.getName().endsWith(".json")) {
      System.err.println("Error: Test file must be a .json file");
      System.exit(2);
    }

    try {
      // Read the test file
      byte[] jsonData = Files.readAllBytes(testFile.toPath());

      // Create executor for the specified fork
      StateTestExecutor executor = new StateTestExecutor(fork);

      // Create output writer
      DumpTraceWriter dumpWriter;
      if (outputFile != null) {
        dumpWriter =
            new DumpTraceWriter(outputFile.getAbsolutePath(), includeFiltered, fork);
      } else {
        // Write to stdout
        dumpWriter =
            new DumpTraceWriter(
                new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8)),
                includeFiltered,
                fork);
      }

      // Execute with tracing and dump
      try {
        executor.executeWithTracingAndDump(jsonData, dumpWriter);
      } finally {
        dumpWriter.close();
      }

      // Exit successfully
      System.exit(0);

    } catch (Exception e) {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
      System.exit(2);
    }
  }
}
