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
package org.hyperledger.besu.testfuzz.tracing;

import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.operation.Operation;
import org.hyperledger.besu.evm.operation.Operation.OperationResult;
import org.hyperledger.besu.evm.tracing.OperationTracer;

import java.util.ArrayList;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;

/**
 * An OperationTracer that captures EVM execution steps and normalizes them for cross-VM trace
 * comparison. This tracer produces MD5 hashes compatible with geth's statetest fuzzer.
 *
 * <p>Usage:
 *
 * <pre>{@code
 * NormalizingOperationTracer tracer = new NormalizingOperationTracer();
 * // ... execute transaction with tracer ...
 * TracingResult result = tracer.finish(worldState.rootHash().toHexString());
 * }</pre>
 */
public class NormalizingOperationTracer implements OperationTracer {

  private final TraceNormalizer normalizer;

  /** Creates a new NormalizingOperationTracer. */
  public NormalizingOperationTracer() {
    this.normalizer = new TraceNormalizer();
  }

  @Override
  public void tracePostExecution(final MessageFrame frame, final OperationResult operationResult) {
    CanonicalOpLog log = new CanonicalOpLog();

    // Depth: MessageFrame.getDepth() returns 0 for rootmost call
    // Trace format uses 1-indexed depth
    log.setDepth(frame.getDepth() + 1);

    // Program counter
    log.setPc(frame.getPC());

    // Gas remaining (before operation cost is deducted, we capture post-execution state)
    log.setGas(frame.getRemainingGas());

    // Opcode
    Operation op = frame.getCurrentOperation();
    if (op != null) {
      log.setOp(op.getOpcode());
      log.setOpName(op.getName());
    } else {
      log.setOp(0);
      log.setOpName("UNKNOWN");
    }

    // EOF fields (section, functionDepth) - TODO: add when EOF support is needed
    // log.setSection(...)
    // log.setFunctionDepth(...)

    // Capture last 6 stack items
    int stackSize = frame.stackSize();
    List<Bytes> stack = new ArrayList<>();
    int start = Math.max(0, stackSize - 6);
    for (int i = start; i < stackSize; i++) {
      // getStackItem(0) is top of stack, we want oldest to newest
      // So we read from (stackSize - 1 - i) perspective
      // Actually, we need to capture from bottom to top for last 6
      int offset = stackSize - 1 - i;
      try {
        Bytes item = frame.getStackItem(offset);
        stack.add(item);
      } catch (Exception e) {
        // Stack underflow - add zero
        stack.add(Bytes.EMPTY);
      }
    }
    log.setStack(stack);

    normalizer.processLog(log);
  }

  /**
   * Finishes tracing and returns the normalized trace hash result.
   *
   * @param stateRoot the post-execution state root (0x prefixed hex)
   * @return the tracing result containing MD5 hash
   */
  public TracingResult finish(final String stateRoot) {
    byte[] hash = normalizer.finish(stateRoot);
    String hashHex = bytesToHex(hash);
    return new TracingResult(hashHex, stateRoot, normalizer.getLineCount());
  }

  /** Resets the tracer for reuse. */
  public void reset() {
    normalizer.reset();
  }

  /**
   * Converts bytes to lowercase hex string.
   *
   * @param bytes the bytes
   * @return lowercase hex string
   */
  private static String bytesToHex(final byte[] bytes) {
    StringBuilder hex = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      hex.append(String.format("%02x", b & 0xFF));
    }
    return hex.toString();
  }
}
