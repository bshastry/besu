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
package org.hyperledger.besu.testfuzz.statetest;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

/**
 * Opcode-aware mutation strategy. Knows about opcode semantics and mutates to related opcodes.
 * Ported from goevmlab.
 */
public class OpcodeSmartMutationStrategy implements MutationStrategy {

  private final Random rng;

  // Related opcode groups - mutating within groups tests edge cases
  private static final Map<Integer, int[]> OPCODE_GROUPS = new HashMap<>();

  static {
    // Arithmetic
    int[] arithmetic = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B};
    for (int op : arithmetic) {
      OPCODE_GROUPS.put(op, arithmetic);
    }

    // Comparison
    int[] comparison = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    for (int op : comparison) {
      OPCODE_GROUPS.put(op, comparison);
    }

    // Bitwise
    int[] bitwise = {0x16, 0x17, 0x18, 0x19};
    for (int op : bitwise) {
      OPCODE_GROUPS.put(op, bitwise);
    }

    // Memory
    int[] memory = {0x51, 0x52, 0x53};
    for (int op : memory) {
      OPCODE_GROUPS.put(op, memory);
    }

    // Storage
    int[] storage = {0x54, 0x55};
    for (int op : storage) {
      OPCODE_GROUPS.put(op, storage);
    }

    // Transient storage (EIP-1153)
    int[] tstorage = {0x5C, 0x5D};
    for (int op : tstorage) {
      OPCODE_GROUPS.put(op, tstorage);
    }

    // Call variants
    int[] calls = {0xF1, 0xF2, 0xF4, 0xFA};
    for (int op : calls) {
      OPCODE_GROUPS.put(op, calls);
    }

    // Create variants
    int[] creates = {0xF0, 0xF5};
    for (int op : creates) {
      OPCODE_GROUPS.put(op, creates);
    }

    // Return variants
    int[] returns = {0xF3, 0xFD};
    for (int op : returns) {
      OPCODE_GROUPS.put(op, returns);
    }

    // MCOPY (EIP-5656, Cancun)
    int[] mcopy = {0x5E, 0x37, 0x39};
    OPCODE_GROUPS.put(0x5E, mcopy);

    // BLOBHASH (EIP-4844, Cancun)
    int[] blobhash = {0x49, 0x40, 0x41, 0x42, 0x43};
    OPCODE_GROUPS.put(0x49, blobhash);

    // BLOBBASEFEE (EIP-7516, Cancun)
    int[] blobbasefee = {0x4A, 0x48, 0x3A};
    OPCODE_GROUPS.put(0x4A, blobbasefee);
  }

  public OpcodeSmartMutationStrategy() {
    this.rng = new Random();
  }

  public OpcodeSmartMutationStrategy(final long seed) {
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "opcode-smart";
  }

  @Override
  public String description() {
    return "Opcode-aware mutation (replace with related opcodes)";
  }

  @Override
  public int weight() {
    return 15;
  }

  @Override
  public MutationResult mutate(final byte[] data) throws MutationException {
    JsonNode root = JsonMutationHelper.parse(data);
    Map.Entry<String, JsonNode> testEntry = JsonMutationHelper.getFirstTest(root);
    JsonNode test = testEntry.getValue();

    ObjectNode pre = JsonMutationHelper.getPreState(test);
    List<JsonMutationHelper.AccountWithCode> accounts = JsonMutationHelper.getAccountsWithCode(pre);

    if (accounts.isEmpty()) {
      throw new MutationException("No accounts with code found");
    }

    // Select a random account
    JsonMutationHelper.AccountWithCode target = JsonMutationHelper.randomElement(accounts, rng);
    byte[] code = target.getCode();
    byte[] mutatedCode = mutateCode(code);

    // Update the account's code
    target.getAccountNode().set("code", new TextNode(JsonMutationHelper.bytesToHex(mutatedCode)));

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, target.getAddress());
  }

  private byte[] mutateCode(final byte[] code) {
    if (code.length == 0) {
      return code;
    }

    byte[] mutated = Arrays.copyOf(code, code.length);

    List<Integer> mutablePositions = JsonMutationHelper.findMutablePositions(code);
    if (mutablePositions.isEmpty()) {
      return mutated;
    }

    int pos = mutablePositions.get(rng.nextInt(mutablePositions.size()));
    int opcode = code[pos] & 0xFF;

    // Check if we have related opcodes
    int[] related = OPCODE_GROUPS.get(opcode);
    if (related != null && related.length > 1) {
      // Pick a different opcode from the same group
      int newOp;
      do {
        newOp = related[rng.nextInt(related.length)];
      } while (newOp == opcode && related.length > 1);
      mutated[pos] = (byte) newOp;
    } else {
      // Fall back to random mutation
      mutated[pos] = (byte) rng.nextInt(256);
    }

    return mutated;
  }
}
