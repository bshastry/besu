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

import java.util.ArrayList;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;

/**
 * Represents a normalized EVM execution step for cross-VM trace comparison. This format strips
 * client-specific quirks (gasCost, memorySize, returnData, error) to enable deterministic hashing
 * across different Ethereum clients.
 *
 * <p>Field order in canonical marshal (must match geth exactly): depth, pc, [section],
 * [functionDepth], gas, op, opName, stack
 */
public class CanonicalOpLog {

  private int depth;
  private long pc;
  private long section; // EOF only, omit if 0
  private int functionDepth; // EOF only, omit if 0
  private long gas;
  private int op; // opcode as int (0-255)
  private String opName;
  private List<Bytes> stack; // Last 6 items only

  /** Creates a new empty CanonicalOpLog. */
  public CanonicalOpLog() {
    this.stack = new ArrayList<>();
  }

  /**
   * Gets the call depth.
   *
   * @return the depth
   */
  public int getDepth() {
    return depth;
  }

  /**
   * Sets the call depth.
   *
   * @param depth the depth
   */
  public void setDepth(final int depth) {
    this.depth = depth;
  }

  /**
   * Gets the program counter.
   *
   * @return the pc
   */
  public long getPc() {
    return pc;
  }

  /**
   * Sets the program counter.
   *
   * @param pc the pc
   */
  public void setPc(final long pc) {
    this.pc = pc;
  }

  /**
   * Gets the EOF section (0 if not EOF).
   *
   * @return the section
   */
  public long getSection() {
    return section;
  }

  /**
   * Sets the EOF section.
   *
   * @param section the section
   */
  public void setSection(final long section) {
    this.section = section;
  }

  /**
   * Gets the EOF function depth (0 if not EOF).
   *
   * @return the function depth
   */
  public int getFunctionDepth() {
    return functionDepth;
  }

  /**
   * Sets the EOF function depth.
   *
   * @param functionDepth the function depth
   */
  public void setFunctionDepth(final int functionDepth) {
    this.functionDepth = functionDepth;
  }

  /**
   * Gets the remaining gas.
   *
   * @return the gas
   */
  public long getGas() {
    return gas;
  }

  /**
   * Sets the remaining gas.
   *
   * @param gas the gas
   */
  public void setGas(final long gas) {
    this.gas = gas;
  }

  /**
   * Gets the opcode.
   *
   * @return the opcode
   */
  public int getOp() {
    return op;
  }

  /**
   * Sets the opcode.
   *
   * @param op the opcode
   */
  public void setOp(final int op) {
    this.op = op;
  }

  /**
   * Gets the opcode name.
   *
   * @return the opcode name
   */
  public String getOpName() {
    return opName;
  }

  /**
   * Sets the opcode name.
   *
   * @param opName the opcode name
   */
  public void setOpName(final String opName) {
    this.opName = opName;
  }

  /**
   * Gets the stack (last 6 items).
   *
   * @return the stack
   */
  public List<Bytes> getStack() {
    return stack;
  }

  /**
   * Sets the stack (should be last 6 items).
   *
   * @param stack the stack
   */
  public void setStack(final List<Bytes> stack) {
    this.stack = stack != null ? stack : new ArrayList<>();
  }
}
