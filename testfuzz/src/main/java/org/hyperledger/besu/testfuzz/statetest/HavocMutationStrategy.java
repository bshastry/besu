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
import java.util.Random;

/**
 * Havoc mutation strategy - AFL's "havoc" stage.
 * Applies multiple stacked random mutations.
 * Ported from goevmlab.
 */
public class HavocMutationStrategy implements MutationStrategy {

  private final Random rng;

  // Interesting values for replacement
  private static final byte[] INTERESTING_8 = {
      (byte) 0, (byte) 1, (byte) -1, (byte) 16, (byte) 32, (byte) 64, (byte) 100, (byte) 127, (byte) -128
  };

  private static final short[] INTERESTING_16 = {
      (short) 0, (short) 1, (short) -1, (short) 255, (short) 256, (short) 1024, (short) 32767, (short) -32768
  };

  private static final int[] INTERESTING_32 = {
      0, 1, -1, 255, 256, 65535, 65536, Integer.MAX_VALUE, Integer.MIN_VALUE
  };

  public HavocMutationStrategy() {
    this.rng = new Random();
  }

  public HavocMutationStrategy(final long seed) {
    this.rng = new Random(seed);
  }

  @Override
  public String name() {
    return "havoc";
  }

  @Override
  public String description() {
    return "AFL havoc stage (stacked random mutations)";
  }

  @Override
  public int weight() {
    return 12;
  }

  @Override
  public MutationResult mutate(final byte[] data) throws MutationException {
    if (data.length < 2) {
      throw new MutationException("Data too small for havoc");
    }

    byte[] mutated = Arrays.copyOf(data, data.length);

    // Apply 1-16 stacked mutations
    int numMutations = 1 + rng.nextInt(16);
    for (int i = 0; i < numMutations; i++) {
      mutated = applySingleMutation(mutated);
    }

    return new MutationResult(mutated, "havoc:" + numMutations);
  }

  private byte[] applySingleMutation(final byte[] data) {
    if (data.length == 0) {
      return data;
    }

    int op = rng.nextInt(16);

    switch (op) {
      case 0:
        // Flip a bit
        return flipBit(data);
      case 1:
        // Set byte to interesting value
        return setInteresting8(data);
      case 2:
        // Set word to interesting value
        return setInteresting16(data);
      case 3:
        // Set dword to interesting value
        return setInteresting32(data);
      case 4:
        // Subtract from byte
        return subtractFromByte(data);
      case 5:
        // Add to byte
        return addToByte(data);
      case 6:
        // Subtract from word
        return subtractFromWord(data);
      case 7:
        // Add to word
        return addToWord(data);
      case 8:
        // Subtract from dword
        return subtractFromDword(data);
      case 9:
        // Add to dword
        return addToDword(data);
      case 10:
        // Set random byte
        return setRandomByte(data);
      case 11:
        // Delete bytes
        return deleteBytes(data);
      case 12:
        // Clone bytes
        return cloneBytes(data);
      case 13:
        // Overwrite with clone
        return overwriteWithClone(data);
      case 14:
        // Insert random bytes
        return insertRandomBytes(data);
      case 15:
        // Overwrite with random
        return overwriteWithRandom(data);
      default:
        return flipBit(data);
    }
  }

  private byte[] flipBit(final byte[] data) {
    byte[] result = Arrays.copyOf(data, data.length);
    int pos = rng.nextInt(data.length);
    int bit = rng.nextInt(8);
    result[pos] = (byte) (result[pos] ^ (1 << bit));
    return result;
  }

  private byte[] setInteresting8(final byte[] data) {
    byte[] result = Arrays.copyOf(data, data.length);
    int pos = rng.nextInt(data.length);
    result[pos] = INTERESTING_8[rng.nextInt(INTERESTING_8.length)];
    return result;
  }

  private byte[] setInteresting16(final byte[] data) {
    if (data.length < 2) return data;
    byte[] result = Arrays.copyOf(data, data.length);
    int pos = rng.nextInt(data.length - 1);
    short value = INTERESTING_16[rng.nextInt(INTERESTING_16.length)];
    if (rng.nextBoolean()) {
      // Big endian
      result[pos] = (byte) (value >> 8);
      result[pos + 1] = (byte) value;
    } else {
      // Little endian
      result[pos] = (byte) value;
      result[pos + 1] = (byte) (value >> 8);
    }
    return result;
  }

  private byte[] setInteresting32(final byte[] data) {
    if (data.length < 4) return data;
    byte[] result = Arrays.copyOf(data, data.length);
    int pos = rng.nextInt(data.length - 3);
    int value = INTERESTING_32[rng.nextInt(INTERESTING_32.length)];
    if (rng.nextBoolean()) {
      // Big endian
      result[pos] = (byte) (value >> 24);
      result[pos + 1] = (byte) (value >> 16);
      result[pos + 2] = (byte) (value >> 8);
      result[pos + 3] = (byte) value;
    } else {
      // Little endian
      result[pos] = (byte) value;
      result[pos + 1] = (byte) (value >> 8);
      result[pos + 2] = (byte) (value >> 16);
      result[pos + 3] = (byte) (value >> 24);
    }
    return result;
  }

  private byte[] subtractFromByte(final byte[] data) {
    byte[] result = Arrays.copyOf(data, data.length);
    int pos = rng.nextInt(data.length);
    int delta = rng.nextInt(35) + 1;
    result[pos] = (byte) (result[pos] - delta);
    return result;
  }

  private byte[] addToByte(final byte[] data) {
    byte[] result = Arrays.copyOf(data, data.length);
    int pos = rng.nextInt(data.length);
    int delta = rng.nextInt(35) + 1;
    result[pos] = (byte) (result[pos] + delta);
    return result;
  }

  private byte[] subtractFromWord(final byte[] data) {
    if (data.length < 2) return data;
    byte[] result = Arrays.copyOf(data, data.length);
    int pos = rng.nextInt(data.length - 1);
    int delta = rng.nextInt(35) + 1;
    int value = ((result[pos] & 0xFF) << 8) | (result[pos + 1] & 0xFF);
    value -= delta;
    result[pos] = (byte) (value >> 8);
    result[pos + 1] = (byte) value;
    return result;
  }

  private byte[] addToWord(final byte[] data) {
    if (data.length < 2) return data;
    byte[] result = Arrays.copyOf(data, data.length);
    int pos = rng.nextInt(data.length - 1);
    int delta = rng.nextInt(35) + 1;
    int value = ((result[pos] & 0xFF) << 8) | (result[pos + 1] & 0xFF);
    value += delta;
    result[pos] = (byte) (value >> 8);
    result[pos + 1] = (byte) value;
    return result;
  }

  private byte[] subtractFromDword(final byte[] data) {
    if (data.length < 4) return data;
    byte[] result = Arrays.copyOf(data, data.length);
    int pos = rng.nextInt(data.length - 3);
    int delta = rng.nextInt(35) + 1;
    int value = ((result[pos] & 0xFF) << 24) | ((result[pos + 1] & 0xFF) << 16) |
        ((result[pos + 2] & 0xFF) << 8) | (result[pos + 3] & 0xFF);
    value -= delta;
    result[pos] = (byte) (value >> 24);
    result[pos + 1] = (byte) (value >> 16);
    result[pos + 2] = (byte) (value >> 8);
    result[pos + 3] = (byte) value;
    return result;
  }

  private byte[] addToDword(final byte[] data) {
    if (data.length < 4) return data;
    byte[] result = Arrays.copyOf(data, data.length);
    int pos = rng.nextInt(data.length - 3);
    int delta = rng.nextInt(35) + 1;
    int value = ((result[pos] & 0xFF) << 24) | ((result[pos + 1] & 0xFF) << 16) |
        ((result[pos + 2] & 0xFF) << 8) | (result[pos + 3] & 0xFF);
    value += delta;
    result[pos] = (byte) (value >> 24);
    result[pos + 1] = (byte) (value >> 16);
    result[pos + 2] = (byte) (value >> 8);
    result[pos + 3] = (byte) value;
    return result;
  }

  private byte[] setRandomByte(final byte[] data) {
    byte[] result = Arrays.copyOf(data, data.length);
    int pos = rng.nextInt(data.length);
    result[pos] = (byte) (rng.nextInt(255) + 1);
    return result;
  }

  private byte[] deleteBytes(final byte[] data) {
    if (data.length < 4) return data;
    int delLen = rng.nextInt(Math.min(16, data.length / 4)) + 1;
    int delPos = rng.nextInt(data.length - delLen);
    byte[] result = new byte[data.length - delLen];
    System.arraycopy(data, 0, result, 0, delPos);
    System.arraycopy(data, delPos + delLen, result, delPos, data.length - delPos - delLen);
    return result;
  }

  private byte[] cloneBytes(final byte[] data) {
    if (data.length < 4) return data;
    int cloneLen = rng.nextInt(Math.min(16, data.length / 4)) + 1;
    int srcPos = rng.nextInt(data.length - cloneLen);
    int dstPos = rng.nextInt(data.length + 1);
    byte[] result = new byte[data.length + cloneLen];
    System.arraycopy(data, 0, result, 0, dstPos);
    System.arraycopy(data, srcPos, result, dstPos, cloneLen);
    System.arraycopy(data, dstPos, result, dstPos + cloneLen, data.length - dstPos);
    return result;
  }

  private byte[] overwriteWithClone(final byte[] data) {
    if (data.length < 4) return data;
    byte[] result = Arrays.copyOf(data, data.length);
    int cloneLen = rng.nextInt(Math.min(16, data.length / 4)) + 1;
    int srcPos = rng.nextInt(data.length - cloneLen);
    int dstPos = rng.nextInt(data.length - cloneLen);
    System.arraycopy(data, srcPos, result, dstPos, cloneLen);
    return result;
  }

  private byte[] insertRandomBytes(final byte[] data) {
    int insertLen = rng.nextInt(16) + 1;
    int insertPos = rng.nextInt(data.length + 1);
    byte[] result = new byte[data.length + insertLen];
    System.arraycopy(data, 0, result, 0, insertPos);
    for (int i = 0; i < insertLen; i++) {
      result[insertPos + i] = (byte) rng.nextInt(256);
    }
    System.arraycopy(data, insertPos, result, insertPos + insertLen, data.length - insertPos);
    return result;
  }

  private byte[] overwriteWithRandom(final byte[] data) {
    if (data.length < 2) return data;
    byte[] result = Arrays.copyOf(data, data.length);
    int overwriteLen = rng.nextInt(Math.min(16, data.length / 2)) + 1;
    int pos = rng.nextInt(data.length - overwriteLen + 1);
    for (int i = 0; i < overwriteLen; i++) {
      result[pos + i] = (byte) rng.nextInt(256);
    }
    return result;
  }
}
