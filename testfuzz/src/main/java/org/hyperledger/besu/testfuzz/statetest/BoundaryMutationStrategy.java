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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

/**
 * Boundary mutation strategy. Replaces numeric values with AFL-inspired boundary/interesting values
 * that are likely to trigger edge case bugs. Ported from goevmlab mutations/boundary.go
 */
public class BoundaryMutationStrategy implements MutationStrategy {

  private final Random rng;

  // EVM-specific interesting gas values (uint64)
  private static final String[] INTERESTING_GAS_BOUNDARIES = {
    "0x0", // Zero
    "0x1", // Minimum
    "0x51bf", // 21000-1 (just below intrinsic)
    "0x5208", // 21000 (intrinsic gas cost)
    "0x5209", // 21000+1 (just above intrinsic)
    "0x8fc", // 2300 (CALL stipend)
    "0xa28", // 2600 (COLD_ACCOUNT_ACCESS EIP-2929)
    "0x64", // 100 (WARM_STORAGE_READ)
    "0x4e20", // 20000 (SSTORE_SET)
    "0x1388", // 5000 (SSTORE_RESET)
    "0x7d00", // 32000 (CREATE cost)
    "0xcf08", // 53000 (CREATE2 cost region)
    "0x1c9c380", // 30000000 (block gas limit)
    "0xffffffff", // Max uint32
    "0xffffffffffff", // Large uint48
    "0xffffffffffffffff", // Max uint64
  };

  // EVM-specific interesting value amounts (big.Int as hex)
  // Note: Max uint256 is excluded as it causes false positives in realistic scenarios.
  private static final String[] INTERESTING_VALUE_BOUNDARIES = {
    "0x0", // Zero
    "0x1", // 1 wei
    "0xde0b6b3a7640000", // 1 ether
    "0x8ac7230489e80000", // 10 ether
    "0x152d02c7e14af6800000", // 100,000 ether
    "0x7fffffffffffffff", // Max int64
    "0xffffffffffffffff", // Max uint64
    "0xffffffffffffffffffffffffffffffff", // Max uint128
    // "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // Max uint256 -
    // disabled
    "0x8000000000000000000000000000000000000000000000000000000000000000", // Sign bit set
    "0x0000000000000000000000000000000000000000000000000000000000000001", // 1 with leading zeros
  };

  // EVM-specific interesting timestamps
  private static final String[] INTERESTING_TIMESTAMP_BOUNDARIES = {
    "0x0", // Genesis
    "0x1", // 1 second
    "0x7fffffff", // Max int32 (Y2K38)
    "0xffffffff", // Max uint32
    "0x5f5e100", // 100M seconds (~3 years)
    "0x65a1bc00", // ~2024 timestamp
    "0x77359400", // Year 2033 approx
  };

  // EVM-specific interesting block numbers
  private static final String[] INTERESTING_BLOCK_NUMBER_BOUNDARIES = {
    "0x0", // Genesis
    "0x1", // Block 1
    "0x1fff", // 8191 (EIP-2935 ring buffer size - 1)
    "0x2000", // 8192 (EIP-2935 ring buffer size)
    "0x2001", // 8193
    "0xf4240", // 1,000,000
    "0x989680", // 10,000,000
    "0xffffffff", // Max uint32
  };

  // EVM-specific interesting base fees
  private static final String[] INTERESTING_BASE_FEE_BOUNDARIES = {
    "0x1", // Minimum
    "0x7", // Very low
    "0x3b9aca00", // 1 gwei
    "0x77359400", // 2 gwei
    "0xe8d4a51000", // 1000 gwei
  };

  /** Describes a target for boundary mutation. */
  private static class BoundaryTarget {
    final String section;
    final String field;
    final boolean isArray;
    final String[] boundaries;
    final String description;
    final boolean enabled;

    BoundaryTarget(
        final String section,
        final String field,
        final boolean isArray,
        final String[] boundaries,
        final String description,
        final boolean enabled) {
      this.section = section;
      this.field = field;
      this.isArray = isArray;
      this.boundaries = boundaries;
      this.description = description;
      this.enabled = enabled;
    }
  }

  // Note: env fields are disabled - they cause false positives because mutating block
  // environment creates unrealistic test scenarios that don't represent real consensus bugs.
  private static final BoundaryTarget[] BOUNDARY_TARGETS = {
    new BoundaryTarget("transaction", "gasLimit", true, INTERESTING_GAS_BOUNDARIES, "gas", true),
    new BoundaryTarget("transaction", "value", true, INTERESTING_VALUE_BOUNDARIES, "value", true),
    new BoundaryTarget(
        "transaction", "gasPrice", false, INTERESTING_BASE_FEE_BOUNDARIES, "gasPrice", true),
    new BoundaryTarget(
        "transaction",
        "maxFeePerGas",
        false,
        INTERESTING_BASE_FEE_BOUNDARIES,
        "maxFeePerGas",
        true),
    new BoundaryTarget(
        "transaction",
        "maxPriorityFeePerGas",
        false,
        INTERESTING_BASE_FEE_BOUNDARIES,
        "maxPriorityFeePerGas",
        true),
    // Environment fields - disabled: mutating block env causes false positives
    new BoundaryTarget(
        "env", "currentGasLimit", false, INTERESTING_GAS_BOUNDARIES, "blockGasLimit", false),
    new BoundaryTarget(
        "env", "currentTimestamp", false, INTERESTING_TIMESTAMP_BOUNDARIES, "timestamp", false),
    new BoundaryTarget(
        "env", "currentNumber", false, INTERESTING_BLOCK_NUMBER_BOUNDARIES, "blockNumber", false),
    new BoundaryTarget(
        "env", "currentBaseFee", false, INTERESTING_BASE_FEE_BOUNDARIES, "baseFee", false),
  };

  /** Creates a new BoundaryMutationStrategy. */
  public BoundaryMutationStrategy() {
    this.rng = new Random();
  }

  /**
   * Creates a new BoundaryMutationStrategy with a seed.
   *
   * @param seed the random seed
   */
  public BoundaryMutationStrategy(final long seed) {
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "boundary";
  }

  @Override
  public String description() {
    return "Replace values with AFL-inspired boundary/interesting values";
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

    // Find available targets (only enabled ones)
    List<BoundaryTarget> available = new ArrayList<>();
    for (BoundaryTarget target : BOUNDARY_TARGETS) {
      if (!target.enabled) {
        continue;
      }
      if (test.has(target.section)) {
        JsonNode section = test.get(target.section);
        if (section.isObject() && section.has(target.field)) {
          available.add(target);
        }
      }
    }

    // Also add account balance boundaries
    if (test.has("pre")) {
      JsonNode pre = test.get("pre");
      if (pre.isObject() && pre.size() > 0) {
        available.add(
            new BoundaryTarget(
                "pre", "balance", false, INTERESTING_VALUE_BOUNDARIES, "accountBalance", true));
      }
    }

    if (available.isEmpty()) {
      throw new MutationException("No boundary mutation targets found");
    }

    // Select random target
    BoundaryTarget target = available.get(rng.nextInt(available.size()));

    // Select random boundary value
    String newValue = target.boundaries[rng.nextInt(target.boundaries.length)];

    // Apply mutation
    if ("pre".equals(target.section)) {
      mutatePreField((ObjectNode) test, target.field, newValue);
    } else {
      mutateSectionField((ObjectNode) test, target, newValue);
    }

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, target.description + "=" + newValue);
  }

  private void mutateSectionField(
      final ObjectNode test, final BoundaryTarget target, final String newValue) {
    ObjectNode section = (ObjectNode) test.get(target.section);

    if (target.isArray) {
      ArrayNode newArray = section.putArray(target.field);
      newArray.add(newValue);
    } else {
      section.set(target.field, new TextNode(newValue));
    }
  }

  private void mutatePreField(final ObjectNode test, final String field, final String newValue)
      throws MutationException {
    ObjectNode pre = (ObjectNode) test.get("pre");

    if (pre.size() == 0) {
      throw new MutationException("No accounts in pre-state");
    }

    // Select random account
    List<String> accounts = new ArrayList<>();
    pre.fieldNames().forEachRemaining(accounts::add);
    String addr = accounts.get(rng.nextInt(accounts.size()));

    ObjectNode account = (ObjectNode) pre.get(addr);
    account.set(field, new TextNode(newValue));
  }
}
