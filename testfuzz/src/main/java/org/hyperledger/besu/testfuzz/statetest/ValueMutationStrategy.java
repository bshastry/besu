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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

import java.math.BigInteger;
import java.util.Map;
import java.util.Random;

/**
 * Value mutation strategy.
 * Mutates transaction values (wei amounts) to test value transfer edge cases.
 * Ported from goevmlab.
 */
public class ValueMutationStrategy implements MutationStrategy {

  private final Random rng;

  // Interesting value amounts for fuzzing (in wei)
  private static final BigInteger[] INTERESTING_VALUES = {
      BigInteger.ZERO,
      BigInteger.ONE,
      BigInteger.valueOf(21000),                    // Base tx cost
      BigInteger.valueOf(1_000_000_000),            // 1 gwei
      BigInteger.valueOf(1_000_000_000_000_000_000L), // 1 ether
      new BigInteger("ffffffffffffffff", 16),       // Max uint64
      new BigInteger("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16), // Max uint256
      BigInteger.valueOf(2).pow(128).subtract(BigInteger.ONE),  // Max uint128
      BigInteger.valueOf(2).pow(64).subtract(BigInteger.ONE),   // Max uint64
      BigInteger.valueOf(2).pow(32).subtract(BigInteger.ONE),   // Max uint32
  };

  public ValueMutationStrategy() {
    this.rng = new Random();
  }

  /**
   * Creates a new ValueMutationStrategy with a seed.
   *
   * @param seed the random seed
   */
  public ValueMutationStrategy(final long seed) {
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "value";
  }

  @Override
  public String description() {
    return "Transaction value mutations (boundaries, overflow)";
  }

  @Override
  public int weight() {
    return 8;
  }

  @Override
  public MutationResult mutate(final byte[] data) throws MutationException {
    JsonNode root = JsonMutationHelper.parse(data);
    Map.Entry<String, JsonNode> testEntry = JsonMutationHelper.getFirstTest(root);
    JsonNode test = testEntry.getValue();

    ObjectNode tx = JsonMutationHelper.getTransaction(test);
    JsonNode valueNode = tx.get("value");

    if (valueNode == null) {
      throw new MutationException("No value field in transaction");
    }

    BigInteger newValue = selectNewValue(valueNode);
    String newValueHex = "0x" + newValue.toString(16);

    // Value can be an array or single value
    if (valueNode.isArray()) {
      ArrayNode valueArray = tx.putArray("value");
      valueArray.add(newValueHex);
    } else {
      tx.set("value", new TextNode(newValueHex));
    }

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, "value=" + newValueHex);
  }

  private BigInteger selectNewValue(final JsonNode currentValueNode) {
    int strategy = rng.nextInt(100);

    if (strategy < 40) {
      // Use interesting value
      return INTERESTING_VALUES[rng.nextInt(INTERESTING_VALUES.length)];
    } else if (strategy < 70) {
      // Parse current and adjust
      BigInteger currentValue = parseValue(currentValueNode);
      BigInteger delta = BigInteger.valueOf(rng.nextLong() & Long.MAX_VALUE);
      if (rng.nextBoolean()) {
        return currentValue.add(delta);
      } else {
        BigInteger result = currentValue.subtract(delta);
        return result.compareTo(BigInteger.ZERO) < 0 ? BigInteger.ZERO : result;
      }
    } else {
      // Random value
      byte[] randomBytes = new byte[32];
      rng.nextBytes(randomBytes);
      randomBytes[0] = (byte) (randomBytes[0] & 0x7F); // Ensure positive
      return new BigInteger(1, randomBytes);
    }
  }

  private BigInteger parseValue(final JsonNode node) {
    String hex;
    if (node.isArray() && node.size() > 0) {
      hex = node.get(0).asText();
    } else if (node.isTextual()) {
      hex = node.asText();
    } else {
      return BigInteger.ZERO;
    }

    if (hex == null || hex.isEmpty()) {
      return BigInteger.ZERO;
    }

    String cleanHex = hex.startsWith("0x") ? hex.substring(2) : hex;
    if (cleanHex.isEmpty()) {
      return BigInteger.ZERO;
    }

    try {
      return new BigInteger(cleanHex, 16);
    } catch (NumberFormatException e) {
      return BigInteger.ZERO;
    }
  }
}
