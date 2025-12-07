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
import java.util.Random;

/**
 * Havoc mutation strategy - AFL's "havoc" stage.
 * Applies multiple stacked mutations using all base strategies (AFL havoc stage).
 * This is AFL's most effective mutation stage for finding deep bugs.
 * It stacks 2-128 random mutations per test case, dramatically increasing
 * mutation diversity.
 * Ported from goevmlab mutations/havoc.go
 *
 * <p>Note: HavocStrategy is not included in its own base strategies to prevent recursion.
 */
public class HavocMutationStrategy implements MutationStrategy {

  private final List<MutationStrategy> strategies;
  private final Random rng;

  /** Creates a new HavocMutationStrategy with all base strategies. */
  public HavocMutationStrategy() {
    this.rng = new Random();
    this.strategies = buildBaseStrategies();
  }

  /**
   * Creates a new HavocMutationStrategy with a seed.
   *
   * @param seed the random seed
   */
  public HavocMutationStrategy(final long seed) {
    this.rng = new Random(seed);
    this.strategies = buildBaseStrategies();
  }

  /**
   * Creates a new HavocMutationStrategy with custom strategies.
   * This is useful for testing or when you want to limit the mutation pool.
   *
   * @param strategies the list of base strategies
   */
  public HavocMutationStrategy(final List<MutationStrategy> strategies) {
    this.rng = new Random();
    this.strategies = new ArrayList<>(strategies);
  }

  /**
   * Creates a new HavocMutationStrategy with custom strategies and a seed.
   *
   * @param strategies the list of base strategies
   * @param seed the random seed
   */
  public HavocMutationStrategy(final List<MutationStrategy> strategies, final long seed) {
    this.rng = new Random(seed);
    this.strategies = new ArrayList<>(strategies);
  }

  /**
   * Builds the default list of base strategies.
   * Note: HavocStrategy itself is NOT included to prevent infinite recursion.
   */
  private static List<MutationStrategy> buildBaseStrategies() {
    List<MutationStrategy> strategies = new ArrayList<>();
    strategies.add(new BytecodeMutationStrategy());
    strategies.add(new OpcodeSmartMutationStrategy());
    strategies.add(new GasMutationStrategy());
    strategies.add(new ValueMutationStrategy());
    strategies.add(new CalldataMutationStrategy());
    strategies.add(new StorageMutationStrategy());
    strategies.add(new ArithmeticMutationStrategy());
    strategies.add(new BoundaryMutationStrategy());
    strategies.add(new DictionaryMutationStrategy());
    strategies.add(new BitFlipMutationStrategy());
    strategies.add(new BlockOpsMutationStrategy());
    strategies.add(new TransactionFieldMutationStrategy());
    strategies.add(new AccountFieldMutationStrategy());
    // Note: SplicingStrategy NOT included by default - requires corpus access
    return strategies;
  }

  @Override
  public String name() {
    return "havoc";
  }

  @Override
  public String description() {
    return "AFL havoc stage: stack 2-128 random mutations";
  }

  @Override
  public int weight() {
    return 5; // Lower weight since havoc is expensive and should be used less frequently
  }

  @Override
  public MutationResult mutate(final byte[] data) throws MutationException {
    if (strategies.isEmpty()) {
      throw new MutationException("No strategies configured");
    }

    // Stack count: 2^(1 + random(0-6)) = 2, 4, 8, 16, 32, 64, or 128
    int stackPow = 1 + rng.nextInt(7);
    int stackCount = 1 << stackPow;

    byte[] result = data.clone();
    int successCount = 0;

    for (int i = 0; i < stackCount; i++) {
      // Select random strategy (uniform distribution - AFL style)
      MutationStrategy strategy = strategies.get(rng.nextInt(strategies.size()));

      try {
        MutationResult mutationResult = strategy.mutate(result);
        if (mutationResult != null && mutationResult.getData() != null) {
          result = mutationResult.getData();
          successCount++;
        }
      } catch (MutationException e) {
        // Continue even on errors - some mutations may not apply to certain test cases
      }
    }

    if (successCount == 0) {
      throw new MutationException("All havoc mutations failed");
    }

    // Return a summary of applied mutations
    return new MutationResult(result, "havoc[" + successCount + "/" + stackCount + "]");
  }

  /**
   * Returns the list of base strategies used by this havoc strategy.
   * This is useful for testing to verify no infinite recursion.
   *
   * @return the list of strategies
   */
  public List<MutationStrategy> getStrategies() {
    return new ArrayList<>(strategies);
  }
}
