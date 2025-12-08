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

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

/**
 * Splicing mutation strategy. Combines bytecode from different corpus inputs (AFL splicing stage).
 * AFL's splicing finds a point where two inputs differ and creates a hybrid by combining the prefix
 * of one with the suffix of another. Ported from goevmlab mutations/splicing.go
 */
public class SplicingMutationStrategy implements MutationStrategy {

  private final CorpusProvider corpus;
  private final Random rng;

  /**
   * Interface for providing corpus access for splicing operations. This allows the splicing
   * strategy to access other corpus entries without depending on the full corpus implementation.
   */
  public interface CorpusProvider {
    /**
     * Returns a random input from the corpus.
     *
     * @return the random input bytes
     * @throws MutationException if no input is available
     */
    byte[] getRandomInput() throws MutationException;

    /**
     * Returns the number of inputs in the corpus.
     *
     * @return the input count
     */
    int getInputCount();
  }

  /**
   * Creates a new SplicingMutationStrategy with corpus access.
   *
   * @param corpus the corpus provider, may be null
   */
  public SplicingMutationStrategy(final CorpusProvider corpus) {
    this.corpus = corpus;
    this.rng = new Random();
  }

  /**
   * Creates a new SplicingMutationStrategy with corpus access and a seed.
   *
   * @param corpus the corpus provider, may be null
   * @param seed the random seed
   */
  public SplicingMutationStrategy(final CorpusProvider corpus, final long seed) {
    this.corpus = corpus;
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "splicing";
  }

  @Override
  public String description() {
    return "AFL splicing: combine bytecode from different corpus inputs";
  }

  @Override
  public int weight() {
    return 4; // Lower weight since it requires corpus access and is more expensive
  }

  @Override
  public MutationResult mutate(final byte[] data) throws MutationException {
    // Check corpus availability
    if (corpus == null || corpus.getInputCount() < 2) {
      throw new MutationException("Splicing requires corpus with at least 2 inputs");
    }

    // Get another random input from corpus
    byte[] other = corpus.getRandomInput();

    // Extract bytecode from both inputs
    BytecodeInfo currentInfo = extractBytecode(data);
    if (currentInfo == null || currentInfo.code.length < 4) {
      throw new MutationException("Current input has no suitable bytecode");
    }

    BytecodeInfo otherInfo = extractBytecode(other);
    if (otherInfo == null || otherInfo.code.length < 4) {
      throw new MutationException("Other input has no suitable bytecode");
    }

    // Find splice point and combine
    byte[] spliced = spliceBytecode(currentInfo.code, otherInfo.code);
    if (spliced == null || Arrays.equals(spliced, currentInfo.code)) {
      throw new MutationException("Splicing did not produce different bytecode");
    }

    // Replace bytecode in original test
    return replaceBytecode(data, currentInfo.address, spliced);
  }

  /**
   * Extracts the first account's bytecode from a state test.
   *
   * @param data the test JSON bytes
   * @return the bytecode info, or null if not found
   */
  private BytecodeInfo extractBytecode(final byte[] data) throws MutationException {
    JsonNode root = JsonMutationHelper.parse(data);
    Map.Entry<String, JsonNode> testEntry = JsonMutationHelper.getFirstTest(root);
    JsonNode test = testEntry.getValue();

    ObjectNode pre = JsonMutationHelper.getPreState(test);
    List<JsonMutationHelper.AccountWithCode> accounts = JsonMutationHelper.getAccountsWithCode(pre);

    if (accounts.isEmpty()) {
      return null;
    }

    JsonMutationHelper.AccountWithCode account = accounts.get(0);
    return new BytecodeInfo(account.getCode(), account.getAddress());
  }

  /**
   * Combines two bytecode sequences at a differing point. This implements AFL's splice algorithm:
   * find first and last differing positions, pick a random point between them, and create a hybrid.
   *
   * @param a the first bytecode
   * @param b the second bytecode
   * @return the spliced bytecode, or null if splicing is not possible
   */
  private byte[] spliceBytecode(final byte[] a, final byte[] b) {
    if (a.length < 4 || b.length < 4) {
      return null;
    }

    // Find first and last differing positions
    int minLen = Math.min(a.length, b.length);

    int firstDiff = -1;
    int lastDiff = -1;
    for (int i = 0; i < minLen; i++) {
      if (a[i] != b[i]) {
        if (firstDiff == -1) {
          firstDiff = i;
        }
        lastDiff = i;
      }
    }

    // Need at least 2 bytes between first and last diff for meaningful splice
    if (firstDiff < 0 || lastDiff - firstDiff < 2) {
      return null;
    }

    // Pick splice point between first and last diff
    int spliceAt = firstDiff + rng.nextInt(lastDiff - firstDiff);

    // Create hybrid: [a: 0..spliceAt] + [b: spliceAt..end]
    int resultLen = spliceAt + (b.length - spliceAt);
    byte[] result = new byte[resultLen];
    System.arraycopy(a, 0, result, 0, spliceAt);
    System.arraycopy(b, spliceAt, result, spliceAt, b.length - spliceAt);

    return result;
  }

  /**
   * Replaces bytecode at the given address in the test data.
   *
   * @param data the original test JSON bytes
   * @param address the account address
   * @param newCode the new bytecode
   * @return the mutation result
   */
  private MutationResult replaceBytecode(
      final byte[] data, final String address, final byte[] newCode) throws MutationException {
    JsonNode root = JsonMutationHelper.parse(data);
    Map.Entry<String, JsonNode> testEntry = JsonMutationHelper.getFirstTest(root);
    JsonNode test = testEntry.getValue();

    ObjectNode pre = JsonMutationHelper.getPreState(test);
    JsonNode accountNode = pre.get(address);

    if (accountNode == null || !accountNode.isObject()) {
      throw new MutationException("Account not found: " + address);
    }

    ObjectNode account = (ObjectNode) accountNode;
    account.set("code", new TextNode(JsonMutationHelper.bytesToHex(newCode)));

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, "spliced:" + address);
  }

  /** Holds bytecode and its address. */
  private static class BytecodeInfo {
    final byte[] code;
    final String address;

    BytecodeInfo(final byte[] code, final String address) {
      this.code = code;
      this.address = address;
    }
  }
}
