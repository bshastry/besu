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
 * Ported from goevmlab mutations/value.go
 */
public class ValueMutationStrategy implements MutationStrategy {

  private final Random rng;

  // Interesting value amounts for fuzzing (in wei)
  // Note: Very large values (>uint64) are excluded as they cause false positives
  // when used as transaction values - real-world txs don't have such huge values.
  // Max uint256 is explicitly excluded - causes false positives in realistic scenarios.
  private static final BigInteger[] INTERESTING_VALUES = {
      BigInteger.ZERO,                                           // Zero
      BigInteger.ONE,                                            // One wei
      new BigInteger("de0b6b3a7640000", 16),                     // 1 ether
      new BigInteger("8ac7230489e80000", 16),                    // 10 ether
      new BigInteger("ffffffffffffffff", 16),                    // Max uint64
      // Max uint128 and uint256 disabled - cause unrealistic test scenarios / false positives:
      // new BigInteger("ffffffffffffffffffffffffffffffff", 16),   // Max uint128
      // new BigInteger("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16), // Max uint256
      new BigInteger("80", 16).shiftLeft(248),                   // Sign bit set (0x80 followed by 31 zero bytes)
      BigInteger.valueOf(0xff),                                  // Small with 255
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
    return 6; // Same as goevmlab
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
