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
 * Account field mutation strategy. Mutates account balance and nonce in pre-state. Ported from
 * goevmlab mutations/accountfields.go
 */
public class AccountFieldMutationStrategy implements MutationStrategy {

  private final Random rng;

  // Interesting balance values for mutation
  // Note: U256_MAX excluded - causes false positives (REVM aborts on balance overflow, geth wraps)
  private static final String[] INTERESTING_BALANCES = {
    "0x0", // Zero
    "0x1", // 1 wei
    "0xde0b6b3a7640000", // 1 ether
    "0x6f05b59d3b20000", // 0.5 ether
    "0x1bc16d674ec80000", // 2 ether
    "0x56bc75e2d63100000", // 100 ether
  };

  // Interesting nonce values for account mutation
  private static final String[] INTERESTING_ACCOUNT_NONCES = {
    "0x0", "0x1", "0xff", "0x100", "0xffff", "0xffffffff",
  };

  /** Creates a new AccountFieldMutationStrategy. */
  public AccountFieldMutationStrategy() {
    this.rng = new Random();
  }

  /**
   * Creates a new AccountFieldMutationStrategy with a seed.
   *
   * @param seed the random seed
   */
  public AccountFieldMutationStrategy(final long seed) {
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "accountfields";
  }

  @Override
  public String description() {
    return "Mutate account balance and nonce in pre-state";
  }

  @Override
  public int weight() {
    return 6;
  }

  @Override
  public MutationResult mutate(final byte[] data) throws MutationException {
    JsonNode root = JsonMutationHelper.parse(data);
    Map.Entry<String, JsonNode> testEntry = JsonMutationHelper.getFirstTest(root);
    JsonNode test = testEntry.getValue();

    ObjectNode pre = JsonMutationHelper.getPreState(test);

    if (pre.size() == 0) {
      throw new MutationException("No accounts in pre-state");
    }

    // Select random account
    List<String> accounts = new ArrayList<>();
    pre.fieldNames().forEachRemaining(accounts::add);
    String addr = accounts.get(rng.nextInt(accounts.size()));

    ObjectNode account = (ObjectNode) pre.get(addr);

    // 50% chance: mutate balance, 50% chance: mutate nonce
    String desc;
    if (rng.nextBoolean()) {
      // Mutate balance
      String newValue = INTERESTING_BALANCES[rng.nextInt(INTERESTING_BALANCES.length)];
      account.set("balance", new TextNode(newValue));
      desc = "pre[" + addr + "].balance=" + newValue;
    } else {
      // Mutate nonce
      String newValue = INTERESTING_ACCOUNT_NONCES[rng.nextInt(INTERESTING_ACCOUNT_NONCES.length)];
      account.set("nonce", new TextNode(newValue));
      desc = "pre[" + addr + "].nonce=" + newValue;
    }

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, desc);
  }
}
