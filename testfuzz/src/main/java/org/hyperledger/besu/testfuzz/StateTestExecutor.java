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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.besu.ethereum.referencetests.ReferenceTestProtocolSchedules.shouldClearEmptyAccounts;

import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.datatypes.BlobGas;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.mainnet.MainnetTransactionProcessor;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSpec;
import org.hyperledger.besu.ethereum.mainnet.TransactionValidationParams;
import org.hyperledger.besu.ethereum.processing.TransactionProcessingResult;
import org.hyperledger.besu.ethereum.referencetests.GeneralStateTestCaseEipSpec;
import org.hyperledger.besu.ethereum.referencetests.GeneralStateTestCaseSpec;
import org.hyperledger.besu.ethereum.referencetests.ReferenceTestProtocolSchedules;
import org.hyperledger.besu.ethereum.referencetests.ReferenceTestWorldState;
import org.hyperledger.besu.evm.account.Account;
import org.hyperledger.besu.evm.internal.EvmConfiguration;
import org.hyperledger.besu.evm.tracing.OperationTracer;
import org.hyperledger.besu.evm.worldstate.WorldUpdater;
import org.hyperledger.besu.testfuzz.tracing.NormalizingOperationTracer;
import org.hyperledger.besu.testfuzz.tracing.TracingResult;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.tuweni.bytes.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Executes Ethereum state tests directly without IPC overhead. This class provides direct access to
 * Besu's transaction processor for high-performance fuzzing.
 */
public class StateTestExecutor {

  private static final Logger LOG = LoggerFactory.getLogger(StateTestExecutor.class);

  private final ObjectMapper objectMapper;
  private final JavaType stateTestType;
  private final ReferenceTestProtocolSchedules protocolSchedules;
  private final String defaultFork;

  // Statistics
  private final AtomicLong totalExecutions = new AtomicLong(0);
  private final AtomicLong successfulExecutions = new AtomicLong(0);
  private final AtomicLong parseErrors = new AtomicLong(0);
  private final AtomicLong executionErrors = new AtomicLong(0);
  private final AtomicLong skippedTests = new AtomicLong(0);

  /** Result of executing a state test. */
  public static class ExecutionResult {
    private final boolean success;
    private final String stateRoot;
    private final String error;
    private final long gasUsed;
    private final boolean crashed;

    private ExecutionResult(
        final boolean success,
        final String stateRoot,
        final String error,
        final long gasUsed,
        final boolean crashed) {
      this.success = success;
      this.stateRoot = stateRoot;
      this.error = error;
      this.gasUsed = gasUsed;
      this.crashed = crashed;
    }

    /**
     * Creates a successful execution result.
     *
     * @param stateRoot the resulting state root
     * @param gasUsed the gas used
     * @return the execution result
     */
    public static ExecutionResult success(final String stateRoot, final long gasUsed) {
      return new ExecutionResult(true, stateRoot, null, gasUsed, false);
    }

    /**
     * Creates a parse error result.
     *
     * @param error the error message
     * @return the execution result
     */
    public static ExecutionResult parseError(final String error) {
      return new ExecutionResult(false, null, error, 0, false);
    }

    /**
     * Creates an execution error result.
     *
     * @param error the error message
     * @return the execution result
     */
    public static ExecutionResult executionError(final String error) {
      return new ExecutionResult(false, null, error, 0, false);
    }

    /**
     * Creates a crash result.
     *
     * @param error the error message
     * @return the execution result
     */
    public static ExecutionResult crash(final String error) {
      return new ExecutionResult(false, null, error, 0, true);
    }

    /**
     * Creates a skipped result.
     *
     * @param reason the reason for skipping
     * @return the execution result
     */
    public static ExecutionResult skipped(final String reason) {
      return new ExecutionResult(true, null, reason, 0, false);
    }

    /**
     * Returns true if the execution was successful.
     *
     * @return true if successful
     */
    public boolean isSuccess() {
      return success;
    }

    /**
     * Returns the state root.
     *
     * @return the state root
     */
    public String getStateRoot() {
      return stateRoot;
    }

    /**
     * Returns the error message.
     *
     * @return the error message
     */
    public String getError() {
      return error;
    }

    /**
     * Returns the gas used.
     *
     * @return the gas used
     */
    public long getGasUsed() {
      return gasUsed;
    }

    /**
     * Returns true if this was a crash.
     *
     * @return true if crashed
     */
    public boolean isCrashed() {
      return crashed;
    }
  }

  /** Creates a new StateTestExecutor with default fork (Prague). */
  public StateTestExecutor() {
    this("Prague");
  }

  /**
   * Creates a new StateTestExecutor with specified default fork.
   *
   * @param defaultFork the default fork to use when not specified in test
   */
  public StateTestExecutor(final String defaultFork) {
    // Initialize signature algorithm for mainnet
    SignatureAlgorithmFactory.setDefaultInstance();

    this.objectMapper = new ObjectMapper();
    this.stateTestType =
        objectMapper
            .getTypeFactory()
            .constructParametricType(Map.class, String.class, GeneralStateTestCaseSpec.class);
    this.protocolSchedules = ReferenceTestProtocolSchedules.create(EvmConfiguration.DEFAULT);
    this.defaultFork = defaultFork;
  }

  /**
   * Executes a state test from JSON bytes.
   *
   * @param jsonData the state test JSON
   * @return the execution result
   */
  public ExecutionResult execute(final byte[] jsonData) {
    totalExecutions.incrementAndGet();

    // Parse the JSON
    Map<String, GeneralStateTestCaseSpec> stateTests;
    try {
      stateTests = objectMapper.readValue(jsonData, stateTestType);
    } catch (JsonProcessingException e) {
      parseErrors.incrementAndGet();
      return ExecutionResult.parseError("JSON parse error: " + e.getMessage());
    } catch (Exception e) {
      parseErrors.incrementAndGet();
      return ExecutionResult.parseError("Parse error: " + e.getMessage());
    }

    if (stateTests == null || stateTests.isEmpty()) {
      parseErrors.incrementAndGet();
      return ExecutionResult.parseError("Empty or null test");
    }

    // Execute each test case
    for (Map.Entry<String, GeneralStateTestCaseSpec> entry : stateTests.entrySet()) {
      GeneralStateTestCaseSpec spec = entry.getValue();
      if (spec == null) {
        continue;
      }

      Map<String, List<GeneralStateTestCaseEipSpec>> finalStateSpecs = spec.finalStateSpecs();
      if (finalStateSpecs == null || finalStateSpecs.isEmpty()) {
        continue;
      }

      for (Map.Entry<String, List<GeneralStateTestCaseEipSpec>> forkEntry :
          finalStateSpecs.entrySet()) {
        List<GeneralStateTestCaseEipSpec> eipSpecs = forkEntry.getValue();
        if (eipSpecs == null) {
          continue;
        }

        for (GeneralStateTestCaseEipSpec eipSpec : eipSpecs) {
          try {
            ExecutionResult result = executeSpec(eipSpec);
            if (result.isCrashed()) {
              return result; // Propagate crashes immediately
            }
            if (result.isSuccess()) {
              successfulExecutions.incrementAndGet();
            }
            // Continue processing other specs even if one fails
          } catch (Exception e) {
            // This is a potential crash - rethrow for fuzzer to catch
            executionErrors.incrementAndGet();
            LOG.error("Execution exception: {}", e.getMessage(), e);
            return ExecutionResult.crash(
                "Exception: " + e.getClass().getName() + ": " + e.getMessage());
          }
        }
      }
    }

    successfulExecutions.incrementAndGet();
    return ExecutionResult.success("completed", 0);
  }

  /** Executes a single EIP spec. */
  private ExecutionResult executeSpec(final GeneralStateTestCaseEipSpec spec) {
    if (spec == null) {
      return ExecutionResult.skipped("null spec");
    }

    BlockHeader blockHeader = spec.getBlockHeader();
    if (blockHeader == null) {
      return ExecutionResult.skipped("null block header");
    }

    Transaction transaction = spec.getTransaction(0);
    if (transaction == null) {
      // Transaction was invalid during parsing - this is expected for some mutated tests
      return ExecutionResult.skipped("invalid transaction");
    }

    ReferenceTestWorldState initialWorldState = spec.getInitialWorldState();
    if (initialWorldState == null) {
      return ExecutionResult.skipped("null world state");
    }

    // Check gas limit constraint (same as evmtool)
    // This caused the deadlock in the Go fuzzer!
    if (transaction.getGasLimit() > blockHeader.getGasLimit() - blockHeader.getGasUsed()) {
      skippedTests.incrementAndGet();
      return ExecutionResult.skipped("tx gas > block gas remaining");
    }

    ReferenceTestWorldState worldState = initialWorldState.copy();

    String forkName = spec.getFork();
    if (forkName == null || forkName.isEmpty()) {
      forkName = defaultFork;
    }

    ProtocolSchedule protocolSchedule = protocolSchedules.getByName(forkName);
    if (protocolSchedule == null) {
      return ExecutionResult.skipped("unsupported fork: " + forkName);
    }

    ProtocolSpec protocolSpec = protocolSchedule.getByBlockHeader(blockHeader);
    MainnetTransactionProcessor processor = protocolSpec.getTransactionProcessor();
    WorldUpdater worldStateUpdater = worldState.updater();

    // Calculate blob gas price
    BlobGas excessBlobGas = blockHeader.getExcessBlobGas().orElse(BlobGas.ZERO);
    Wei blobGasPrice = protocolSpec.getFeeMarket().blobGasPricePerGas(excessBlobGas);

    // Process the transaction
    TransactionProcessingResult result =
        processor.processTransaction(
            worldStateUpdater,
            blockHeader,
            transaction,
            blockHeader.getCoinbase(),
            OperationTracer.NO_TRACING,
            (__, blockNumber) -> Hash.hash(Bytes.wrap(Long.toString(blockNumber).getBytes(UTF_8))),
            TransactionValidationParams.processingBlock(),
            blobGasPrice);

    // Only commit state if transaction was valid
    if (!result.isInvalid()) {
      if (shouldClearEmptyAccounts(spec.getFork())) {
        Account coinbase = worldStateUpdater.getOrCreate(spec.getBlockHeader().getCoinbase());
        if (coinbase != null && coinbase.isEmpty()) {
          worldStateUpdater.deleteAccount(coinbase.getAddress());
        }
        Account sender = worldStateUpdater.getAccount(transaction.getSender());
        if (sender != null && sender.isEmpty()) {
          worldStateUpdater.deleteAccount(sender.getAddress());
        }
      }
      worldStateUpdater.commit();
      worldState.persist(blockHeader);
    }

    long gasUsed = transaction.getGasLimit() - result.getGasRemaining();
    String stateRoot = worldState.rootHash().toHexString();

    return ExecutionResult.success(stateRoot, gasUsed);
  }

  /**
   * Executes a state test with trace normalization for cross-VM comparison. This method captures
   * EVM execution steps and produces an MD5 hash compatible with geth's statetest fuzzer.
   *
   * @param jsonData the state test JSON
   * @return the tracing result containing MD5 hash, state root, and line count
   */
  public TracingResult executeWithTracing(final byte[] jsonData) {
    totalExecutions.incrementAndGet();

    // Parse the JSON
    Map<String, GeneralStateTestCaseSpec> stateTests;
    try {
      stateTests = objectMapper.readValue(jsonData, stateTestType);
    } catch (Exception e) {
      parseErrors.incrementAndGet();
      return new TracingResult(null, null, 0);
    }

    if (stateTests == null || stateTests.isEmpty()) {
      parseErrors.incrementAndGet();
      return new TracingResult(null, null, 0);
    }

    // Create tracer for this execution
    NormalizingOperationTracer tracer = new NormalizingOperationTracer();
    String finalStateRoot = null;

    // Execute each test case
    for (Map.Entry<String, GeneralStateTestCaseSpec> entry : stateTests.entrySet()) {
      GeneralStateTestCaseSpec spec = entry.getValue();
      if (spec == null) {
        continue;
      }

      Map<String, List<GeneralStateTestCaseEipSpec>> finalStateSpecs = spec.finalStateSpecs();
      if (finalStateSpecs == null || finalStateSpecs.isEmpty()) {
        continue;
      }

      for (Map.Entry<String, List<GeneralStateTestCaseEipSpec>> forkEntry :
          finalStateSpecs.entrySet()) {
        List<GeneralStateTestCaseEipSpec> eipSpecs = forkEntry.getValue();
        if (eipSpecs == null) {
          continue;
        }

        for (GeneralStateTestCaseEipSpec eipSpec : eipSpecs) {
          try {
            String stateRoot = executeSpecWithTracing(eipSpec, tracer);
            if (stateRoot != null) {
              finalStateRoot = stateRoot;
              successfulExecutions.incrementAndGet();
            }
          } catch (Exception e) {
            executionErrors.incrementAndGet();
            LOG.debug("Execution exception during tracing: {}", e.getMessage());
          }
        }
      }
    }

    // Finish tracing and get hash
    if (finalStateRoot != null) {
      return tracer.finish(finalStateRoot);
    } else {
      return new TracingResult(null, null, 0);
    }
  }

  /**
   * Executes a single EIP spec with tracing.
   *
   * @param spec the EIP spec
   * @param tracer the operation tracer
   * @return the state root after execution, or null if skipped/failed
   */
  private String executeSpecWithTracing(
      final GeneralStateTestCaseEipSpec spec, final OperationTracer tracer) {
    if (spec == null) {
      return null;
    }

    BlockHeader blockHeader = spec.getBlockHeader();
    if (blockHeader == null) {
      return null;
    }

    Transaction transaction = spec.getTransaction(0);
    if (transaction == null) {
      return null;
    }

    ReferenceTestWorldState initialWorldState = spec.getInitialWorldState();
    if (initialWorldState == null) {
      return null;
    }

    // Check gas limit constraint
    if (transaction.getGasLimit() > blockHeader.getGasLimit() - blockHeader.getGasUsed()) {
      skippedTests.incrementAndGet();
      return null;
    }

    ReferenceTestWorldState worldState = initialWorldState.copy();

    String forkName = spec.getFork();
    if (forkName == null || forkName.isEmpty()) {
      forkName = defaultFork;
    }

    ProtocolSchedule protocolSchedule = protocolSchedules.getByName(forkName);
    if (protocolSchedule == null) {
      return null;
    }

    ProtocolSpec protocolSpec = protocolSchedule.getByBlockHeader(blockHeader);
    MainnetTransactionProcessor processor = protocolSpec.getTransactionProcessor();
    WorldUpdater worldStateUpdater = worldState.updater();

    // Calculate blob gas price
    BlobGas excessBlobGas = blockHeader.getExcessBlobGas().orElse(BlobGas.ZERO);
    Wei blobGasPrice = protocolSpec.getFeeMarket().blobGasPricePerGas(excessBlobGas);

    // Process the transaction WITH tracing
    TransactionProcessingResult result =
        processor.processTransaction(
            worldStateUpdater,
            blockHeader,
            transaction,
            blockHeader.getCoinbase(),
            tracer, // Use the normalizing tracer
            (__, blockNumber) -> Hash.hash(Bytes.wrap(Long.toString(blockNumber).getBytes(UTF_8))),
            TransactionValidationParams.processingBlock(),
            blobGasPrice);

    // Only commit state if transaction was valid
    if (!result.isInvalid()) {
      if (shouldClearEmptyAccounts(spec.getFork())) {
        Account coinbase = worldStateUpdater.getOrCreate(spec.getBlockHeader().getCoinbase());
        if (coinbase != null && coinbase.isEmpty()) {
          worldStateUpdater.deleteAccount(coinbase.getAddress());
        }
        Account sender = worldStateUpdater.getAccount(transaction.getSender());
        if (sender != null && sender.isEmpty()) {
          worldStateUpdater.deleteAccount(sender.getAddress());
        }
      }
      worldStateUpdater.commit();
      worldState.persist(blockHeader);
    }

    return worldState.rootHash().toHexString();
  }

  /**
   * Returns execution statistics.
   *
   * @return the statistics string
   */
  public String getStats() {
    return String.format(
        "total=%d success=%d parse_err=%d exec_err=%d skipped=%d",
        totalExecutions.get(),
        successfulExecutions.get(),
        parseErrors.get(),
        executionErrors.get(),
        skippedTests.get());
  }

  /** Resets statistics. */
  public void resetStats() {
    totalExecutions.set(0);
    successfulExecutions.set(0);
    parseErrors.set(0);
    executionErrors.set(0);
    skippedTests.set(0);
  }

  /**
   * Returns the total executions.
   *
   * @return the total executions
   */
  public long getTotalExecutions() {
    return totalExecutions.get();
  }

  /**
   * Returns the successful executions.
   *
   * @return the successful executions
   */
  public long getSuccessfulExecutions() {
    return successfulExecutions.get();
  }

  /**
   * Returns the parse errors.
   *
   * @return the parse errors
   */
  public long getParseErrors() {
    return parseErrors.get();
  }

  /**
   * Returns the execution errors.
   *
   * @return the execution errors
   */
  public long getExecutionErrors() {
    return executionErrors.get();
  }

  /**
   * Returns the skipped tests.
   *
   * @return the skipped tests
   */
  public long getSkippedTests() {
    return skippedTests.get();
  }
}
