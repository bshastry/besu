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
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Storage mutation strategy.
 * Mutates pre-state storage to test state management.
 * Ported from goevmlab mutations/storage.go
 */
public class StorageMutationStrategy implements MutationStrategy {

  private final Random rng;

  // Interesting storage slots (32 bytes each)
  private static final String[] INTERESTING_SLOTS = {
      "0x0000000000000000000000000000000000000000000000000000000000000000", // Slot 0
      "0x0000000000000000000000000000000000000000000000000000000000000001", // Slot 1
      "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // Max slot
      "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe", // Max - 1
      "0x00000000000000000000000000000000000000000000000000000000000000ff", // Slot 255
  };

  // Interesting storage values (32 bytes each)
  private static final String[] INTERESTING_STORAGE_VALUES = {
      "0x0000000000000000000000000000000000000000000000000000000000000000", // Zero (delete)
      "0x0000000000000000000000000000000000000000000000000000000000000001", // Non-zero minimal
      "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // Max value
      "0xdededededededededededededededededededededededededededededededede", // Pattern
      "0x8000000000000000000000000000000000000000000000000000000000000000", // Sign bit
  };

  /** Creates a new StorageMutationStrategy. */
  public StorageMutationStrategy() {
    this.rng = new Random();
  }

  /**
   * Creates a new StorageMutationStrategy with a seed.
   *
   * @param seed the random seed
   */
  public StorageMutationStrategy(final long seed) {
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "storage";
  }

  @Override
  public String description() {
    return "Storage mutations (keys, values, warm/cold)";
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

    // Find accounts with storage or code (prefer these for storage mutations)
    List<String> candidates = new ArrayList<>();
    Iterator<Map.Entry<String, JsonNode>> fields = pre.fields();
    while (fields.hasNext()) {
      Map.Entry<String, JsonNode> entry = fields.next();
      String address = entry.getKey();
      JsonNode account = entry.getValue();

      if (!account.isObject()) {
        continue;
      }

      // Prefer accounts with existing storage or code
      if (account.has("storage") || account.has("code")) {
        candidates.add(address);
      }
    }

    // If no candidates found, use any account
    if (candidates.isEmpty()) {
      fields = pre.fields();
      if (fields.hasNext()) {
        candidates.add(fields.next().getKey());
      }
    }

    if (candidates.isEmpty()) {
      throw new MutationException("No accounts found in pre-state");
    }

    // Select a random account
    String targetAddr = candidates.get(rng.nextInt(candidates.size()));
    ObjectNode account = (ObjectNode) pre.get(targetAddr);

    // Get or create storage
    ObjectNode storage;
    if (account.has("storage") && account.get("storage").isObject()) {
      storage = (ObjectNode) account.get("storage");
    } else {
      storage = account.putObject("storage");
    }

    int strategy = rng.nextInt(100);
    String mutation;

    if (strategy < 40) {
      // Add new storage slot
      String slot = INTERESTING_SLOTS[rng.nextInt(INTERESTING_SLOTS.length)];
      String value = INTERESTING_STORAGE_VALUES[rng.nextInt(INTERESTING_STORAGE_VALUES.length)];
      storage.set(slot, new TextNode(value));
      mutation = "add slot " + truncateSlot(slot);
    } else if (strategy < 70 && storage.size() > 0) {
      // Modify existing slot
      String existingSlot = storage.fieldNames().next();
      String newValue = INTERESTING_STORAGE_VALUES[rng.nextInt(INTERESTING_STORAGE_VALUES.length)];
      storage.set(existingSlot, new TextNode(newValue));
      mutation = "mod slot " + truncateSlot(existingSlot);
    } else if (strategy < 85 && storage.size() > 0) {
      // Delete slot (set to zero)
      String existingSlot = storage.fieldNames().next();
      storage.set(existingSlot, new TextNode(INTERESTING_STORAGE_VALUES[0])); // Zero
      mutation = "zero slot " + truncateSlot(existingSlot);
    } else {
      // Add random slot
      byte[] randSlot = new byte[32];
      rng.nextBytes(randSlot);
      String slotHex = JsonMutationHelper.bytesToHex(randSlot);
      String value = INTERESTING_STORAGE_VALUES[rng.nextInt(INTERESTING_STORAGE_VALUES.length)];
      storage.set(slotHex, new TextNode(value));
      mutation = "random slot";
    }

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, mutation);
  }

  private static String truncateSlot(final String slot) {
    if (slot.length() <= 10) {
      return slot;
    }
    return slot.substring(0, 10);
  }
}
