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

import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * BitFlip mutation strategy.
 * Performs AFL-style systematic bit flipping mutations on bytecode.
 * AFL uses FLIP1/FLIP2/FLIP4/FLIP8 stages that flip consecutive bits at each position.
 * Ported from goevmlab mutations/bitflip.go
 */
public class BitFlipMutationStrategy implements MutationStrategy {

  private final Random rng;

  /** AFL's FLIP1, FLIP2, FLIP4, FLIP8 stages. */
  private static final int[] FLIP_SIZES = {1, 2, 4, 8};

  /** Creates a new BitFlipMutationStrategy. */
  public BitFlipMutationStrategy() {
    this.rng = new Random();
  }

  /**
   * Creates a new BitFlipMutationStrategy with a seed.
   *
   * @param seed the random seed
   */
  public BitFlipMutationStrategy(final long seed) {
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "bitflip";
  }

  @Override
  public String description() {
    return "AFL-style bit flipping (1/2/4/8 consecutive bits)";
  }

  @Override
  public int weight() {
    return 6;
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

    JsonMutationHelper.AccountWithCode target = JsonMutationHelper.randomElement(accounts, rng);
    byte[] code = target.getCode();

    if (code.length == 0) {
      throw new MutationException("Code is empty");
    }

    // Select flip size: 1, 2, 4, or 8 bits
    int flipSize = FLIP_SIZES[rng.nextInt(FLIP_SIZES.length)];

    byte[] mutatedCode = flipBits(code, flipSize);

    target.getAccountNode().set("code", new TextNode(JsonMutationHelper.bytesToHex(mutatedCode)));

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, "bitflip" + flipSize + ":" + target.getAddress());
  }

  /**
   * Flips numBits consecutive bits starting at a random position.
   *
   * @param data the input data
   * @param numBits the number of consecutive bits to flip
   * @return the mutated data
   */
  private byte[] flipBits(final byte[] data, final int numBits) {
    if (data.length == 0) {
      return data;
    }

    // Calculate total bits available
    int totalBits = data.length * 8;

    // Need at least numBits to flip
    if (totalBits < numBits) {
      return data;
    }

    // Select random starting bit position
    int startBit = rng.nextInt(totalBits - numBits + 1);

    // Create mutated copy
    byte[] result = new byte[data.length];
    System.arraycopy(data, 0, result, 0, data.length);

    // Flip consecutive bits
    for (int i = 0; i < numBits; i++) {
      int bitPos = startBit + i;
      int bytePos = bitPos / 8;
      int bitOffset = bitPos % 8;
      // Flip bit (MSB first ordering, like AFL)
      result[bytePos] = (byte) (result[bytePos] ^ (1 << (7 - bitOffset)));
    }

    return result;
  }
}
