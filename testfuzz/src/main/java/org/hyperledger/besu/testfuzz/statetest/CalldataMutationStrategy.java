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

import java.util.Arrays;
import java.util.Map;
import java.util.Random;

/**
 * Calldata mutation strategy.
 * Mutates transaction input data (calldata).
 * Ported from goevmlab.
 */
public class CalldataMutationStrategy implements MutationStrategy {

  private final Random rng;

  public CalldataMutationStrategy() {
    this.rng = new Random();
  }

  public CalldataMutationStrategy(final long seed) {
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "calldata";
  }

  @Override
  public String description() {
    return "Calldata mutations (bit flip, insert, truncate)";
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

    ObjectNode tx = JsonMutationHelper.getTransaction(test);
    JsonNode dataNode = tx.get("data");

    if (dataNode == null) {
      throw new MutationException("No data field in transaction");
    }

    String description;
    if (dataNode.isArray()) {
      ArrayNode dataArray = (ArrayNode) dataNode;
      if (dataArray.size() == 0) {
        throw new MutationException("Empty data array");
      }

      // Mutate first element
      String currentHex = dataArray.get(0).asText();
      byte[] currentData = JsonMutationHelper.hexToBytes(currentHex);
      byte[] mutatedData = mutateCalldata(currentData);
      String mutatedHex = JsonMutationHelper.bytesToHex(mutatedData);

      ArrayNode newArray = tx.putArray("data");
      newArray.add(mutatedHex);
      description = "data[0]";
    } else {
      String currentHex = dataNode.asText();
      byte[] currentData = JsonMutationHelper.hexToBytes(currentHex);
      byte[] mutatedData = mutateCalldata(currentData);
      String mutatedHex = JsonMutationHelper.bytesToHex(mutatedData);

      tx.set("data", new TextNode(mutatedHex));
      description = "data";
    }

    byte[] result = JsonMutationHelper.serialize(root);
    return new MutationResult(result, description);
  }

  private byte[] mutateCalldata(final byte[] data) {
    if (data.length == 0) {
      // Generate some random calldata
      int size = rng.nextInt(128) + 4;
      byte[] newData = new byte[size];
      rng.nextBytes(newData);
      return newData;
    }

    int strategy = rng.nextInt(100);

    if (strategy < 25) {
      // Bit flip
      byte[] mutated = Arrays.copyOf(data, data.length);
      int pos = rng.nextInt(mutated.length);
      int bit = rng.nextInt(8);
      mutated[pos] = (byte) (mutated[pos] ^ (1 << bit));
      return mutated;
    } else if (strategy < 50) {
      // Byte replacement
      byte[] mutated = Arrays.copyOf(data, data.length);
      int pos = rng.nextInt(mutated.length);
      mutated[pos] = (byte) rng.nextInt(256);
      return mutated;
    } else if (strategy < 70) {
      // Insert bytes
      int insertPos = rng.nextInt(data.length + 1);
      int insertLen = rng.nextInt(32) + 1;
      byte[] mutated = new byte[data.length + insertLen];
      System.arraycopy(data, 0, mutated, 0, insertPos);
      for (int i = 0; i < insertLen; i++) {
        mutated[insertPos + i] = (byte) rng.nextInt(256);
      }
      System.arraycopy(data, insertPos, mutated, insertPos + insertLen, data.length - insertPos);
      return mutated;
    } else if (strategy < 85) {
      // Truncate
      if (data.length <= 4) {
        return data;
      }
      int newLen = rng.nextInt(data.length - 3) + 4;
      return Arrays.copyOf(data, newLen);
    } else {
      // Duplicate a chunk
      if (data.length < 4) {
        return data;
      }
      int srcPos = rng.nextInt(data.length - 2);
      int chunkLen = Math.min(rng.nextInt(16) + 1, data.length - srcPos);
      int dstPos = rng.nextInt(data.length);

      byte[] mutated = new byte[data.length + chunkLen];
      System.arraycopy(data, 0, mutated, 0, dstPos);
      System.arraycopy(data, srcPos, mutated, dstPos, chunkLen);
      System.arraycopy(data, dstPos, mutated, dstPos + chunkLen, data.length - dstPos);
      return mutated;
    }
  }
}
