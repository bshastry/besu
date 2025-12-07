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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.tuweni.bytes.Bytes;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Helper class for JSON manipulation in mutation strategies.
 * Provides utilities for parsing and modifying state test JSON.
 */
public class JsonMutationHelper {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  /**
   * Parses JSON bytes into a JsonNode.
   */
  public static JsonNode parse(final byte[] data) throws MutationStrategy.MutationException {
    try {
      return MAPPER.readTree(data);
    } catch (Exception e) {
      throw new MutationStrategy.MutationException("Failed to parse JSON: " + e.getMessage(), e);
    }
  }

  /**
   * Serializes a JsonNode back to bytes.
   */
  public static byte[] serialize(final JsonNode node) throws MutationStrategy.MutationException {
    try {
      return MAPPER.writeValueAsBytes(node);
    } catch (JsonProcessingException e) {
      throw new MutationStrategy.MutationException("Failed to serialize JSON: " + e.getMessage(), e);
    }
  }

  /**
   * Gets the first test name and data from the root object.
   * State tests have format: { "TestName": { ... } }
   */
  public static Map.Entry<String, JsonNode> getFirstTest(final JsonNode root) throws MutationStrategy.MutationException {
    if (!root.isObject() || root.isEmpty()) {
      throw new MutationStrategy.MutationException("Invalid test format: not an object or empty");
    }

    Iterator<Map.Entry<String, JsonNode>> fields = root.fields();
    if (!fields.hasNext()) {
      throw new MutationStrategy.MutationException("No test found in JSON");
    }

    return fields.next();
  }

  /**
   * Gets the 'pre' state from a test node.
   */
  public static ObjectNode getPreState(final JsonNode test) throws MutationStrategy.MutationException {
    JsonNode pre = test.get("pre");
    if (pre == null || !pre.isObject()) {
      throw new MutationStrategy.MutationException("No 'pre' state found");
    }
    return (ObjectNode) pre;
  }

  /**
   * Gets the 'transaction' object from a test node.
   */
  public static ObjectNode getTransaction(final JsonNode test) throws MutationStrategy.MutationException {
    JsonNode tx = test.get("transaction");
    if (tx == null || !tx.isObject()) {
      throw new MutationStrategy.MutationException("No 'transaction' found");
    }
    return (ObjectNode) tx;
  }

  /**
   * Gets all accounts with code from the pre state.
   */
  public static List<AccountWithCode> getAccountsWithCode(final ObjectNode pre) {
    List<AccountWithCode> accounts = new ArrayList<>();

    Iterator<Map.Entry<String, JsonNode>> fields = pre.fields();
    while (fields.hasNext()) {
      Map.Entry<String, JsonNode> entry = fields.next();
      String address = entry.getKey();
      JsonNode account = entry.getValue();

      if (!account.isObject()) {
        continue;
      }

      JsonNode codeNode = account.get("code");
      if (codeNode == null || !codeNode.isTextual()) {
        continue;
      }

      String codeHex = codeNode.asText();
      byte[] code = hexToBytes(codeHex);
      if (code != null && code.length > 0) {
        accounts.add(new AccountWithCode(address, code, (ObjectNode) account));
      }
    }

    return accounts;
  }

  /**
   * Converts a hex string to bytes.
   */
  public static byte[] hexToBytes(final String hex) {
    if (hex == null || hex.isEmpty()) {
      return new byte[0];
    }

    String cleanHex = hex.startsWith("0x") ? hex.substring(2) : hex;
    if (cleanHex.isEmpty()) {
      return new byte[0];
    }

    // Pad if odd length
    if (cleanHex.length() % 2 != 0) {
      cleanHex = "0" + cleanHex;
    }

    try {
      return Bytes.fromHexString("0x" + cleanHex).toArray();
    } catch (Exception e) {
      return new byte[0];
    }
  }

  /**
   * Converts bytes to a hex string with 0x prefix.
   */
  public static String bytesToHex(final byte[] bytes) {
    if (bytes == null || bytes.length == 0) {
      return "0x";
    }
    return Bytes.wrap(bytes).toHexString();
  }

  /**
   * Parses a hex string as an unsigned long.
   */
  public static long hexToLong(final String hex) {
    if (hex == null || hex.isEmpty()) {
      return 0;
    }

    String cleanHex = hex.startsWith("0x") ? hex.substring(2) : hex;
    if (cleanHex.isEmpty()) {
      return 0;
    }

    try {
      return Long.parseUnsignedLong(cleanHex, 16);
    } catch (NumberFormatException e) {
      return 0;
    }
  }

  /**
   * Formats a long as a hex string with 0x prefix.
   */
  public static String longToHex(final long value) {
    return "0x" + Long.toHexString(value);
  }

  /**
   * Finds positions in bytecode that are opcodes (not PUSH operands).
   */
  public static List<Integer> findMutablePositions(final byte[] code) {
    List<Integer> positions = new ArrayList<>();
    int i = 0;

    while (i < code.length) {
      positions.add(i);
      int opcode = code[i] & 0xFF;

      // PUSH1 (0x60) through PUSH32 (0x7f)
      if (opcode >= 0x60 && opcode <= 0x7f) {
        int pushSize = opcode - 0x5f;
        i += pushSize + 1;
      } else {
        i++;
      }
    }

    return positions;
  }

  /**
   * Selects a random element from a list.
   */
  public static <T> T randomElement(final List<T> list, final Random rng) {
    if (list == null || list.isEmpty()) {
      return null;
    }
    return list.get(rng.nextInt(list.size()));
  }

  /**
   * Represents an account with bytecode.
   */
  public static class AccountWithCode {
    private final String address;
    private final byte[] code;
    private final ObjectNode accountNode;

    public AccountWithCode(final String address, final byte[] code, final ObjectNode accountNode) {
      this.address = address;
      this.code = code;
      this.accountNode = accountNode;
    }

    public String getAddress() {
      return address;
    }

    public byte[] getCode() {
      return code;
    }

    public ObjectNode getAccountNode() {
      return accountNode;
    }
  }
}
