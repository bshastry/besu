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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Arithmetic mutation strategy.
 * Applies AFL-style small arithmetic mutations (+-1-35) to numeric fields.
 * This is effective for finding off-by-one bugs and boundary condition issues.
 * Ported from goevmlab mutations/arithmetic.go
 */
public class ArithmeticMutationStrategy implements MutationStrategy {

  /** AFL's empirically-chosen maximum arithmetic delta. */
  private static final int ARITH_MAX = 35;

  /** Maximum value for a 256-bit unsigned integer (2^256 - 1). */
  private static final BigInteger MAX_UINT256 =
      BigInteger.valueOf(2).pow(256).subtract(BigInteger.ONE);

  private final Random rng;

  /** Creates a new ArithmeticMutationStrategy. */
  public ArithmeticMutationStrategy() {
    this.rng = new Random();
  }

  /**
   * Creates a new ArithmeticMutationStrategy with a seed.
   *
   * @param seed the random seed
   */
  public ArithmeticMutationStrategy(final long seed) {
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "arithmetic";
  }

  @Override
  public String description() {
    return "AFL-style arithmetic mutations (+-1-35 on numeric fields)";
  }

  @Override
  public int weight() {
    return 12; // High weight - effective for edge cases
  }

  /**
   * Describes a target field for arithmetic mutation.
   */
  private static class ArithmeticTarget {
    final String section;
    final String field;
    final boolean isArray;
    final boolean isBigInt;
    final boolean enabled;

    ArithmeticTarget(
        final String section,
        final String field,
        final boolean isArray,
        final boolean isBigInt,
        final boolean enabled) {
      this.section = section;
      this.field = field;
      this.isArray = isArray;
      this.isBigInt = isBigInt;
      this.enabled = enabled;
    }
  }

  // Note: env fields and tx nonce are disabled - they cause false positives because
  // mutating block environment or nonce creates unrealistic test scenarios.
  private static final ArithmeticTarget[] ARITHMETIC_TARGETS = {
      // Transaction fields
      new ArithmeticTarget("transaction", "gasLimit", true, false, true),
      new ArithmeticTarget("transaction", "value", true, true, true),
      new ArithmeticTarget("transaction", "nonce", false, false, false), // disabled: unrealistic
      new ArithmeticTarget("transaction", "gasPrice", false, true, true),
      new ArithmeticTarget("transaction", "maxFeePerGas", false, true, true),
      new ArithmeticTarget("transaction", "maxPriorityFeePerGas", false, true, true),
      // Environment fields - disabled: mutating block env causes false positives
      new ArithmeticTarget("env", "currentGasLimit", false, false, false),
      new ArithmeticTarget("env", "currentNumber", false, false, false),
      new ArithmeticTarget("env", "currentTimestamp", false, false, false),
      new ArithmeticTarget("env", "currentBaseFee", false, true, false),
  };

  @Override
  public MutationResult mutate(final byte[] data) throws MutationException {
    JsonNode root = JsonMutationHelper.parse(data);
    Map.Entry<String, JsonNode> testEntry = JsonMutationHelper.getFirstTest(root);
    JsonNode test = testEntry.getValue();

    // Collect available targets (only enabled ones)
    List<ArithmeticTarget> available = new ArrayList<>();
    for (ArithmeticTarget target : ARITHMETIC_TARGETS) {
      if (target.enabled && test.has(target.section)) {
        JsonNode section = test.get(target.section);
        if (section.isObject() && section.has(target.field)) {
          available.add(target);
        }
      }
    }

    // Also add account fields (balance, nonce in pre-state)
    if (test.has("pre")) {
      JsonNode pre = test.get("pre");
      if (pre.isObject() && pre.size() > 0) {
        available.add(new ArithmeticTarget("pre", "balance", false, true, true));
        available.add(new ArithmeticTarget("pre", "nonce", false, false, true));
      }
    }

    if (available.isEmpty()) {
      throw new MutationException("No mutable arithmetic targets found");
    }

    // Select random target
    ArithmeticTarget target = available.get(rng.nextInt(available.size()));

    // Perform mutation
    String mutationDesc;
    if ("pre".equals(target.section)) {
      mutationDesc = mutatePreField((ObjectNode) test, target);
    } else {
      mutationDesc = mutateSectionField((ObjectNode) test, target);
    }

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, mutationDesc);
  }

  private String mutateSectionField(final ObjectNode test, final ArithmeticTarget target)
      throws MutationException {
    ObjectNode section = (ObjectNode) test.get(target.section);
    JsonNode fieldData = section.get(target.field);

    String newValue;
    if (target.isArray) {
      newValue = mutateArrayField(fieldData, target.isBigInt);
      ArrayNode newArray = section.putArray(target.field);
      newArray.add(newValue);
    } else {
      newValue = mutateSingleField(fieldData, target.isBigInt);
      section.set(target.field, new TextNode(newValue));
    }

    return target.section + "." + target.field + "=" + newValue;
  }

  private String mutatePreField(final ObjectNode test, final ArithmeticTarget target)
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
    if (!account.has(target.field)) {
      throw new MutationException("Account does not have field: " + target.field);
    }

    JsonNode fieldData = account.get(target.field);
    String newValue = mutateSingleField(fieldData, target.isBigInt);
    account.set(target.field, new TextNode(newValue));

    return "pre[" + addr + "]." + target.field + "=" + newValue;
  }

  private String mutateArrayField(final JsonNode data, final boolean isBigInt)
      throws MutationException {
    if (data.isArray() && data.size() > 0) {
      return mutateSingleField(data.get(0), isBigInt);
    }
    return mutateSingleField(data, isBigInt);
  }

  private String mutateSingleField(final JsonNode data, final boolean isBigInt) {
    String hexStr = data.asText();

    if (isBigInt) {
      return mutateBigIntHex(hexStr);
    }
    return mutateUint64Hex(hexStr);
  }

  private String mutateUint64Hex(final String hexStr) {
    long val = JsonMutationHelper.hexToLong(hexStr);
    int delta = 1 + rng.nextInt(ARITH_MAX);

    if (rng.nextBoolean()) {
      val += delta;
    } else {
      val = Math.max(0, val - delta);
    }

    return "0x" + Long.toHexString(val);
  }

  private String mutateBigIntHex(final String hexStr) {
    BigInteger val = hexToBigInt(hexStr);
    BigInteger delta = BigInteger.valueOf(1 + rng.nextInt(ARITH_MAX));

    if (rng.nextBoolean()) {
      val = val.add(delta);
      // Clamp to 256-bit maximum to avoid overflow
      if (val.compareTo(MAX_UINT256) > 0) {
        val = MAX_UINT256;
      }
    } else {
      val = val.subtract(delta);
      if (val.signum() < 0) {
        val = BigInteger.ZERO;
      }
    }

    return "0x" + val.toString(16);
  }

  private static BigInteger hexToBigInt(final String s) {
    String clean = s;
    if (clean.startsWith("0x") || clean.startsWith("0X")) {
      clean = clean.substring(2);
    }
    if (clean.isEmpty()) {
      return BigInteger.ZERO;
    }
    try {
      return new BigInteger(clean, 16);
    } catch (NumberFormatException e) {
      return BigInteger.ZERO;
    }
  }
}
