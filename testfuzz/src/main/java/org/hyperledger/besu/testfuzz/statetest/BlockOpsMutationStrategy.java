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
 * BlockOps mutation strategy.
 * Performs AFL-style block-level mutations on bytecode.
 * AFL uses these extensively in its deterministic and havoc stages for
 * operations like delete, clone, insert, and overwrite.
 * Ported from goevmlab mutations/blockops.go
 */
public class BlockOpsMutationStrategy implements MutationStrategy {

  private final Random rng;

  /** AFL's adaptive max sizes for block operations. */
  private static final int[] MAX_SIZES = {32, 128, 1500, 32768};

  /** Creates a new BlockOpsMutationStrategy. */
  public BlockOpsMutationStrategy() {
    this.rng = new Random();
  }

  /**
   * Creates a new BlockOpsMutationStrategy with a seed.
   *
   * @param seed the random seed
   */
  public BlockOpsMutationStrategy(final long seed) {
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "blockops";
  }

  @Override
  public String description() {
    return "AFL-style block operations (delete, clone, insert, overwrite)";
  }

  @Override
  public int weight() {
    return 7;
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

    // Select operation: weight delete 2x to prevent input bloat
    // 0=delete, 1=clone, 2=insert, 3=overwrite
    int[] ops = {0, 0, 1, 2, 3};
    int op = ops[rng.nextInt(ops.length)];

    String opName;
    byte[] mutatedCode;

    switch (op) {
      case 0:
        opName = "delete";
        mutatedCode = deleteBlock(code);
        break;
      case 1:
        opName = "clone";
        mutatedCode = cloneBlock(code);
        break;
      case 2:
        opName = "insert";
        mutatedCode = insertBlock(code);
        break;
      case 3:
        opName = "overwrite";
        mutatedCode = overwriteBlock(code);
        break;
      default:
        opName = "delete";
        mutatedCode = deleteBlock(code);
    }

    target.getAccountNode().set("code", new TextNode(JsonMutationHelper.bytesToHex(mutatedCode)));

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, opName + ":" + target.getAddress());
  }

  /**
   * Chooses block length using AFL's adaptive sizing.
   *
   * @param limit the maximum limit
   * @return the chosen block length
   */
  private int chooseBlockLen(final int limit) {
    int maxSize = MAX_SIZES[rng.nextInt(MAX_SIZES.length)];
    if (maxSize > limit) {
      maxSize = limit;
    }
    if (maxSize < 1) {
      return 1;
    }
    return 1 + rng.nextInt(maxSize);
  }

  /**
   * Removes a block of bytes from the data.
   *
   * @param data the input data
   * @return the mutated data
   */
  private byte[] deleteBlock(final byte[] data) {
    if (data.length < 4) {
      return data;
    }

    int delLen = chooseBlockLen(data.length - 1);
    if (delLen >= data.length) {
      delLen = data.length - 1;
    }

    int delFrom = rng.nextInt(data.length - delLen);

    byte[] result = new byte[data.length - delLen];
    System.arraycopy(data, 0, result, 0, delFrom);
    System.arraycopy(data, delFrom + delLen, result, delFrom, data.length - delFrom - delLen);
    return result;
  }

  /**
   * Copies a block of bytes to another position.
   *
   * @param data the input data
   * @return the mutated data
   */
  private byte[] cloneBlock(final byte[] data) {
    if (data.length < 2) {
      return data;
    }

    int cloneLen = chooseBlockLen(data.length);
    if (cloneLen > data.length) {
      cloneLen = data.length;
    }

    int from = rng.nextInt(data.length - cloneLen + 1);
    int to = rng.nextInt(data.length);

    byte[] result = new byte[data.length + cloneLen];
    System.arraycopy(data, 0, result, 0, to);
    System.arraycopy(data, from, result, to, cloneLen);
    System.arraycopy(data, to, result, to + cloneLen, data.length - to);
    return result;
  }

  /**
   * Inserts random bytes at a position.
   *
   * @param data the input data
   * @return the mutated data
   */
  private byte[] insertBlock(final byte[] data) {
    int insertLen = chooseBlockLen(256); // Max insert 256 bytes
    int pos = rng.nextInt(data.length + 1);

    byte[] insert = new byte[insertLen];
    rng.nextBytes(insert);

    byte[] result = new byte[data.length + insertLen];
    System.arraycopy(data, 0, result, 0, pos);
    System.arraycopy(insert, 0, result, pos, insertLen);
    System.arraycopy(data, pos, result, pos + insertLen, data.length - pos);
    return result;
  }

  /**
   * Overwrites a block with constant or random bytes.
   *
   * @param data the input data
   * @return the mutated data
   */
  private byte[] overwriteBlock(final byte[] data) {
    if (data.length < 2) {
      return data;
    }

    int overLen = chooseBlockLen(data.length);
    if (overLen > data.length) {
      overLen = data.length;
    }

    int pos = rng.nextInt(data.length - overLen + 1);

    byte[] result = new byte[data.length];
    System.arraycopy(data, 0, result, 0, data.length);

    // 50% constant fill, 50% random
    if (rng.nextBoolean()) {
      byte fill = (byte) rng.nextInt(256);
      for (int i = 0; i < overLen; i++) {
        result[pos + i] = fill;
      }
    } else {
      byte[] random = new byte[overLen];
      rng.nextBytes(random);
      System.arraycopy(random, 0, result, pos, overLen);
    }
    return result;
  }
}
