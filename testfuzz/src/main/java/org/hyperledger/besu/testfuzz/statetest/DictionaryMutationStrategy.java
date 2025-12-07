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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Dictionary mutation strategy.
 * Injects EVM-specific tokens into bytecode.
 * This is inspired by AFL's dictionary mode which maintains a list of
 * domain-specific tokens that are likely to trigger interesting behavior.
 * Ported from goevmlab mutations/dictionary.go
 */
public class DictionaryMutationStrategy implements MutationStrategy {

  private final Random rng;
  private final List<byte[]> dictionary;

  // EVM dictionary - byte sequences likely to trigger interesting behavior
  private static final byte[][] EVM_DICTIONARY = {
      // Critical state-changing opcodes
      {(byte) 0x00},                   // STOP
      {(byte) 0xF1},                   // CALL
      {(byte) 0xF2},                   // CALLCODE
      {(byte) 0xF3},                   // RETURN
      {(byte) 0xF4},                   // DELEGATECALL
      {(byte) 0xF5},                   // CREATE2
      {(byte) 0xFA},                   // STATICCALL
      {(byte) 0xFD},                   // REVERT
      {(byte) 0xFE},                   // INVALID
      {(byte) 0xFF},                   // SELFDESTRUCT
      {(byte) 0xF0},                   // CREATE

      // Storage operations
      {(byte) 0x54},                   // SLOAD
      {(byte) 0x55},                   // SSTORE
      {(byte) 0x5C},                   // TLOAD (EIP-1153)
      {(byte) 0x5D},                   // TSTORE (EIP-1153)

      // Memory operations
      {(byte) 0x51},                   // MLOAD
      {(byte) 0x52},                   // MSTORE
      {(byte) 0x5E},                   // MCOPY (EIP-5656)

      // Common PUSH sequences
      {(byte) 0x60, (byte) 0x00},      // PUSH1 0
      {(byte) 0x60, (byte) 0x01},      // PUSH1 1
      {(byte) 0x60, (byte) 0xFF},      // PUSH1 255
      {(byte) 0x60, (byte) 0x20},      // PUSH1 32 (32 bytes)
      {(byte) 0x61, (byte) 0xFF, (byte) 0xFF}, // PUSH2 0xFFFF
      {(byte) 0x63, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}, // PUSH4 0xFFFFFFFF

      // Jump operations
      {(byte) 0x56},                   // JUMP
      {(byte) 0x57},                   // JUMPI
      {(byte) 0x5B},                   // JUMPDEST

      // Control flow patterns
      {(byte) 0x60, (byte) 0x00, (byte) 0x60, (byte) 0x00, (byte) 0xF3}, // PUSH1 0 PUSH1 0 RETURN
      {(byte) 0x60, (byte) 0x00, (byte) 0x60, (byte) 0x00, (byte) 0xFD}, // PUSH1 0 PUSH1 0 REVERT

      // Block info opcodes
      {(byte) 0x49},                   // BLOBHASH (EIP-4844)
      {(byte) 0x4A},                   // BLOBBASEFEE (EIP-7516)
      {(byte) 0x40},                   // BLOCKHASH
      {(byte) 0x41},                   // COINBASE
      {(byte) 0x42},                   // TIMESTAMP
      {(byte) 0x43},                   // NUMBER
      {(byte) 0x44},                   // PREVRANDAO
      {(byte) 0x45},                   // GASLIMIT
      {(byte) 0x46},                   // CHAINID
      {(byte) 0x48},                   // BASEFEE

      // Precompile call patterns (PUSH1 address)
      {(byte) 0x60, (byte) 0x01},      // PUSH1 1 (ecrecover)
      {(byte) 0x60, (byte) 0x02},      // PUSH1 2 (SHA256)
      {(byte) 0x60, (byte) 0x03},      // PUSH1 3 (RIPEMD160)
      {(byte) 0x60, (byte) 0x04},      // PUSH1 4 (IDENTITY)
      {(byte) 0x60, (byte) 0x05},      // PUSH1 5 (MODEXP)
      {(byte) 0x60, (byte) 0x06},      // PUSH1 6 (BN254_ADD)
      {(byte) 0x60, (byte) 0x07},      // PUSH1 7 (BN254_MUL)
      {(byte) 0x60, (byte) 0x08},      // PUSH1 8 (BN254_PAIRING)
      {(byte) 0x60, (byte) 0x09},      // PUSH1 9 (BLAKE2F)
      {(byte) 0x60, (byte) 0x0A},      // PUSH1 10 (KZG_POINT_EVAL)

      // Common function selectors (for calldata injection)
      {(byte) 0xa9, (byte) 0x05, (byte) 0x9c, (byte) 0xbb}, // transfer(address,uint256)
      {(byte) 0x09, (byte) 0x5e, (byte) 0xa7, (byte) 0xb3}, // approve(address,uint256)
      {(byte) 0x70, (byte) 0xa0, (byte) 0x82, (byte) 0x31}, // balanceOf(address)
      {(byte) 0x18, (byte) 0x16, (byte) 0x0d, (byte) 0xdd}, // totalSupply()

      // Gas-related opcodes
      {(byte) 0x5A},                   // GAS
      {(byte) 0x3A},                   // GASPRICE
      {(byte) 0x47},                   // SELFBALANCE

      // Code/data copy opcodes
      {(byte) 0x39},                   // CODECOPY
      {(byte) 0x37},                   // CALLDATACOPY
      {(byte) 0x3C},                   // EXTCODECOPY
      {(byte) 0x3E},                   // RETURNDATACOPY
  };

  // PUSH32 max uint256 - special case because it's 33 bytes
  private static final byte[] PUSH32_MAX_UINT;

  static {
    PUSH32_MAX_UINT = new byte[33];
    PUSH32_MAX_UINT[0] = 0x7F; // PUSH32
    for (int i = 1; i < 33; i++) {
      PUSH32_MAX_UINT[i] = (byte) 0xFF;
    }
  }

  /** Creates a new DictionaryMutationStrategy. */
  public DictionaryMutationStrategy() {
    this.rng = new Random();
    this.dictionary = buildDictionary();
  }

  /**
   * Creates a new DictionaryMutationStrategy with a seed.
   *
   * @param seed the random seed
   */
  public DictionaryMutationStrategy(final long seed) {
    this.rng = new Random(seed);
    this.dictionary = buildDictionary();
  }

  private static List<byte[]> buildDictionary() {
    List<byte[]> dict = new ArrayList<>();
    for (byte[] entry : EVM_DICTIONARY) {
      dict.add(entry);
    }
    dict.add(PUSH32_MAX_UINT);
    return dict;
  }

  @Override
  public String name() {
    return "dictionary";
  }

  @Override
  public String description() {
    return "Inject EVM-specific dictionary tokens into bytecode";
  }

  @Override
  public int weight() {
    return 8;
  }

  @Override
  public MutationResult mutate(final byte[] data) throws MutationException {
    // 50% overwrite at random position, 50% insert
    if (rng.nextBoolean()) {
      return overwriteToken(data);
    }
    return insertToken(data);
  }

  private MutationResult overwriteToken(final byte[] data) throws MutationException {
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

    if (dictionary.isEmpty()) {
      throw new MutationException("Dictionary is empty");
    }

    // Select random token
    byte[] token = dictionary.get(rng.nextInt(dictionary.size()));

    byte[] mutatedCode;
    if (code.length < token.length) {
      // Code too short, just append
      mutatedCode = new byte[code.length + token.length];
      System.arraycopy(code, 0, mutatedCode, 0, code.length);
      System.arraycopy(token, 0, mutatedCode, code.length, token.length);
    } else {
      int pos = rng.nextInt(code.length - token.length + 1);
      mutatedCode = new byte[code.length];
      System.arraycopy(code, 0, mutatedCode, 0, code.length);
      System.arraycopy(token, 0, mutatedCode, pos, token.length);
    }

    target.getAccountNode().set("code", new TextNode(JsonMutationHelper.bytesToHex(mutatedCode)));

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, "dict_overwrite:" + target.getAddress());
  }

  private MutationResult insertToken(final byte[] data) throws MutationException {
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

    if (dictionary.isEmpty()) {
      throw new MutationException("Dictionary is empty");
    }

    // Select random token
    byte[] token = dictionary.get(rng.nextInt(dictionary.size()));

    // Select insertion position
    int pos = (code.length > 0) ? rng.nextInt(code.length + 1) : 0;

    // Create mutated code with insertion
    byte[] mutatedCode = new byte[code.length + token.length];
    System.arraycopy(code, 0, mutatedCode, 0, pos);
    System.arraycopy(token, 0, mutatedCode, pos, token.length);
    System.arraycopy(code, pos, mutatedCode, pos + token.length, code.length - pos);

    target.getAccountNode().set("code", new TextNode(JsonMutationHelper.bytesToHex(mutatedCode)));

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, "dict_insert:" + target.getAddress());
  }
}
