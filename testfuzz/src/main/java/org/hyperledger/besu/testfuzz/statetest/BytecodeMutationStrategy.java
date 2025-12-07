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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Bytecode mutation strategy.
 * Performs basic bytecode mutation while preserving PUSH operands.
 * Ported from goevmlab.
 */
public class BytecodeMutationStrategy implements MutationStrategy {

  private final Random rng;

  public BytecodeMutationStrategy() {
    this.rng = new Random();
  }

  public BytecodeMutationStrategy(final long seed) {
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "bytecode";
  }

  @Override
  public String description() {
    return "Basic bytecode mutation (flip, inc/dec, bit flip)";
  }

  @Override
  public int weight() {
    return 10;
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

    // Find mutable positions (not PUSH operands)
    List<Integer> mutablePositions = JsonMutationHelper.findMutablePositions(code);
    if (mutablePositions.isEmpty()) {
      // Fall back to random position
      int pos = rng.nextInt(mutated.length);
      mutated[pos] = (byte) rng.nextInt(256);
      return mutated;
    }

    int pos = mutablePositions.get(rng.nextInt(mutablePositions.size()));
    int strategy = rng.nextInt(100);

    if (strategy < 50) {
      // Random byte replacement
      mutated[pos] = (byte) rng.nextInt(256);
    } else if (strategy < 80) {
      // Increment or decrement
      if (rng.nextBoolean()) {
        mutated[pos]++;
      } else {
        mutated[pos]--;
      }
    } else {
      // Bit flip
      int bitPos = rng.nextInt(8);
      mutated[pos] = (byte) (mutated[pos] ^ (1 << bitPos));
    }

    return mutated;
  }
}
