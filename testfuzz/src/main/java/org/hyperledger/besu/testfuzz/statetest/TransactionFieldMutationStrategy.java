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
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

/**
 * Transaction field mutation strategy. Mutates transaction fields that aren't covered by existing
 * strategies (nonce, gasPrice, to, maxFeePerGas, etc.) Ported from goevmlab mutations/txfields.go
 */
public class TransactionFieldMutationStrategy implements MutationStrategy {

  private final Random rng;

  // Interesting 'to' addresses for mutation
  private static final String[] INTERESTING_TO_ADDRESSES = {
    "", // Empty (CREATE)
    "0x0000000000000000000000000000000000000000", // Zero address
    "0x0000000000000000000000000000000000000001", // ECRECOVER
    "0x0000000000000000000000000000000000000002", // SHA256
    "0x0000000000000000000000000000000000000003", // RIPEMD160
    "0x0000000000000000000000000000000000000004", // IDENTITY
    "0x0000000000000000000000000000000000000005", // MODEXP
    "0x0000000000000000000000000000000000000006", // BN254_ADD
    "0x0000000000000000000000000000000000000007", // BN254_MUL
    "0x0000000000000000000000000000000000000008", // BN254_PAIRING
    "0x0000000000000000000000000000000000000009", // BLAKE2F
    "0x000000000000000000000000000000000000000a", // KZG_POINT_EVAL
    "0xffffffffffffffffffffffffffffffffffffffff", // Max address
  };

  // Interesting nonce values for mutation
  private static final String[] INTERESTING_NONCES = {
    "0x0", "0x1", "0xff", "0xffff", "0xffffffff", "0xffffffffffffffff",
  };

  // Interesting gas price values for mutation
  private static final String[] INTERESTING_GAS_PRICES = {
    "0x0",
    "0x1",
    "0x3b9aca00", // 0, 1, 1 gwei
    "0x2540be400", // 10 gwei
    "0x174876e800", // 100 gwei
    "0xffffffffffffffff", // Max uint64
  };

  /** Creates a new TransactionFieldMutationStrategy. */
  public TransactionFieldMutationStrategy() {
    this.rng = new Random();
  }

  /**
   * Creates a new TransactionFieldMutationStrategy with a seed.
   *
   * @param seed the random seed
   */
  public TransactionFieldMutationStrategy(final long seed) {
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "txfields";
  }

  @Override
  public String description() {
    return "Mutate transaction fields (nonce, gasPrice, to, maxFeePerGas)";
  }

  @Override
  public int weight() {
    return 9;
  }

  @Override
  public MutationResult mutate(final byte[] data) throws MutationException {
    JsonNode root = JsonMutationHelper.parse(data);
    Map.Entry<String, JsonNode> testEntry = JsonMutationHelper.getFirstTest(root);
    JsonNode test = testEntry.getValue();

    ObjectNode tx = JsonMutationHelper.getTransaction(test);

    // Define available targets based on what exists in the transaction
    List<TxFieldTarget> targets = new ArrayList<>();

    if (tx.has("nonce")) {
      targets.add(new TxFieldTarget("nonce", this::mutateNonce));
    }
    if (tx.has("gasPrice")) {
      targets.add(new TxFieldTarget("gasPrice", this::mutateGasPrice));
    }
    if (tx.has("to")) {
      targets.add(new TxFieldTarget("to", this::mutateTo));
    }
    if (tx.has("maxFeePerGas")) {
      targets.add(new TxFieldTarget("maxFeePerGas", this::mutateMaxFeePerGas));
    }
    if (tx.has("maxPriorityFeePerGas")) {
      targets.add(new TxFieldTarget("maxPriorityFeePerGas", this::mutateMaxPriorityFeePerGas));
    }
    if (tx.has("maxFeePerBlobGas")) {
      targets.add(new TxFieldTarget("maxFeePerBlobGas", this::mutateMaxFeePerBlobGas));
    }

    if (targets.isEmpty()) {
      throw new MutationException("No mutable transaction fields found");
    }

    // Select random target
    TxFieldTarget target = targets.get(rng.nextInt(targets.size()));

    // Perform mutation
    String desc = target.mutator.mutate(tx);

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, "tx." + desc);
  }

  private String mutateNonce(final ObjectNode tx) {
    String newValue = INTERESTING_NONCES[rng.nextInt(INTERESTING_NONCES.length)];
    tx.set("nonce", new TextNode(newValue));
    return "nonce=" + newValue;
  }

  private String mutateGasPrice(final ObjectNode tx) {
    String newValue = INTERESTING_GAS_PRICES[rng.nextInt(INTERESTING_GAS_PRICES.length)];
    tx.set("gasPrice", new TextNode(newValue));
    return "gasPrice=" + newValue;
  }

  private String mutateTo(final ObjectNode tx) {
    String newValue = INTERESTING_TO_ADDRESSES[rng.nextInt(INTERESTING_TO_ADDRESSES.length)];
    if (newValue.isEmpty()) {
      // For CREATE transactions, use empty string
      tx.set("to", new TextNode(""));
      return "to=(create)";
    }
    tx.set("to", new TextNode(newValue));
    return "to=" + newValue;
  }

  private String mutateMaxFeePerGas(final ObjectNode tx) {
    String newValue = INTERESTING_GAS_PRICES[rng.nextInt(INTERESTING_GAS_PRICES.length)];
    tx.set("maxFeePerGas", new TextNode(newValue));
    return "maxFeePerGas=" + newValue;
  }

  private String mutateMaxPriorityFeePerGas(final ObjectNode tx) {
    String newValue = INTERESTING_GAS_PRICES[rng.nextInt(INTERESTING_GAS_PRICES.length)];
    tx.set("maxPriorityFeePerGas", new TextNode(newValue));
    return "maxPriorityFeePerGas=" + newValue;
  }

  private String mutateMaxFeePerBlobGas(final ObjectNode tx) {
    // Blob gas prices can be similar to regular gas prices
    String newValue = INTERESTING_GAS_PRICES[rng.nextInt(INTERESTING_GAS_PRICES.length)];
    tx.set("maxFeePerBlobGas", new TextNode(newValue));
    return "maxFeePerBlobGas=" + newValue;
  }

  /** Describes a target field for transaction mutation. */
  private static class TxFieldTarget {
    final TxFieldMutator mutator;

    @SuppressWarnings("unused") // Name is informational for debugging
    TxFieldTarget(final String name, final TxFieldMutator mutator) {
      this.mutator = mutator;
    }
  }

  /** Functional interface for transaction field mutators. */
  @FunctionalInterface
  private interface TxFieldMutator {
    String mutate(ObjectNode tx);
  }
}
