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

import java.util.Map;
import java.util.Random;

/**
 * Gas limit mutation strategy.
 * Mutates transaction gas limits to test gas metering edge cases.
 * Ported from goevmlab.
 */
public class GasMutationStrategy implements MutationStrategy {

  private final Random rng;

  // Interesting gas values for fuzzing
  private static final long[] INTERESTING_GAS_VALUES = {
      0L,
      1L,
      21000L,         // Base tx cost
      21001L,         // Just above base
      20999L,         // Just below base
      53000L,         // CREATE cost region
      32000L,         // CALL stipend region
      2300L,          // Call stipend
      2600L,          // COLD_ACCOUNT_ACCESS (EIP-2929)
      100L,           // WARM_STORAGE_READ
      20000L,         // SSTORE_SET
      5000L,          // SSTORE_RESET
      100000L,        // Common test value
      1000000L,       // Higher gas
      10000000L,      // 10M gas
      30000000L,      // Block gas limit region
      0xFFFFFFFFL,    // Max uint32
      0xFFFFFFFFFFFFL // Large value
  };

  public GasMutationStrategy() {
    this.rng = new Random();
  }

  public GasMutationStrategy(final long seed) {
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "gas";
  }

  @Override
  public String description() {
    return "Gas limit mutations (boundaries, just-enough)";
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
    JsonNode gasLimitNode = tx.get("gasLimit");

    if (gasLimitNode == null) {
      throw new MutationException("No gasLimit field in transaction");
    }

    long newGas = selectNewGasValue(gasLimitNode);
    String newGasHex = JsonMutationHelper.longToHex(newGas);

    // Gas limit can be an array or single value
    if (gasLimitNode.isArray()) {
      ArrayNode gasArray = tx.putArray("gasLimit");
      gasArray.add(newGasHex);
    } else {
      tx.set("gasLimit", new TextNode(newGasHex));
    }

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, "gas=" + newGasHex);
  }

  private long selectNewGasValue(final JsonNode currentGasNode) {
    int strategy = rng.nextInt(100);

    if (strategy < 40) {
      // Use interesting value
      return INTERESTING_GAS_VALUES[rng.nextInt(INTERESTING_GAS_VALUES.length)];
    } else if (strategy < 70) {
      // Parse current and adjust
      long currentGas = parseGasValue(currentGasNode);
      int delta = rng.nextInt(10000);
      if (rng.nextBoolean()) {
        return currentGas + delta;
      } else {
        return Math.max(0, currentGas - delta);
      }
    } else {
      // Random gas
      return Math.abs(rng.nextLong() % 30000000L);
    }
  }

  private long parseGasValue(final JsonNode node) {
    if (node.isArray() && node.size() > 0) {
      return JsonMutationHelper.hexToLong(node.get(0).asText());
    } else if (node.isTextual()) {
      return JsonMutationHelper.hexToLong(node.asText());
    }
    return 21000L; // Default
  }
}
