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
 * Combined mutation strategy that selects from multiple strategies based on weights. Ported from
 * goevmlab mutations/strategy.go
 */
public class CombinedMutationStrategy implements MutationStrategy {

  private final List<MutationStrategy> strategies;
  private final int[] weights;
  private final int totalWeight;
  private final Random rng;
  private String lastSelectedStrategy;

  /**
   * Creates a combined strategy with default strategies. This mirrors the Go implementation's
   * NewStrategyFactory().
   *
   * <p>Note: "env" strategy is disabled - mutating block environment (timestamp, number, gasLimit,
   * baseFee) causes false positives as it creates unrealistic test scenarios.
   *
   * <p>Note: "splicing" is NOT registered by default - requires corpus access. Use
   * SplicingMutationStrategy directly when corpus is available.
   */
  public static CombinedMutationStrategy createDefault() {
    List<MutationStrategy> strategies = new ArrayList<>();

    // Core strategies
    strategies.add(new BytecodeMutationStrategy());
    strategies.add(new OpcodeSmartMutationStrategy());
    strategies.add(new GasMutationStrategy());
    strategies.add(new ValueMutationStrategy());
    strategies.add(new CalldataMutationStrategy());
    strategies.add(new StorageMutationStrategy());
    // Note: "env" strategy is disabled - see comment above

    // Phase 1: AFL-inspired strategies
    strategies.add(new ArithmeticMutationStrategy());
    strategies.add(new BoundaryMutationStrategy());
    strategies.add(new DictionaryMutationStrategy());
    strategies.add(new BitFlipMutationStrategy());

    // Phase 2: Block operations and field mutations
    strategies.add(new BlockOpsMutationStrategy());
    strategies.add(new TransactionFieldMutationStrategy());
    strategies.add(new AccountFieldMutationStrategy());

    // Phase 3: Advanced AFL strategies
    strategies.add(new HavocMutationStrategy());
    // Note: "splicing" is NOT registered by default - requires corpus access

    return new CombinedMutationStrategy(strategies);
  }

  /**
   * Creates a combined strategy with all strategies including splicing. This mirrors the Go
   * implementation's NewStrategyFactory() + splicing registration.
   *
   * @param corpusProvider the corpus provider for splicing mutations
   * @return a new CombinedMutationStrategy with splicing enabled
   */
  public static CombinedMutationStrategy createWithSplicing(
      final SplicingMutationStrategy.CorpusProvider corpusProvider) {
    List<MutationStrategy> strategies = new ArrayList<>();

    // Core strategies
    strategies.add(new BytecodeMutationStrategy());
    strategies.add(new OpcodeSmartMutationStrategy());
    strategies.add(new GasMutationStrategy());
    strategies.add(new ValueMutationStrategy());
    strategies.add(new CalldataMutationStrategy());
    strategies.add(new StorageMutationStrategy());
    // Note: "env" strategy is disabled - causes false positives

    // Phase 1: AFL-inspired strategies
    strategies.add(new ArithmeticMutationStrategy());
    strategies.add(new BoundaryMutationStrategy());
    strategies.add(new DictionaryMutationStrategy());
    strategies.add(new BitFlipMutationStrategy());

    // Phase 2: Block operations and field mutations
    strategies.add(new BlockOpsMutationStrategy());
    strategies.add(new TransactionFieldMutationStrategy());
    strategies.add(new AccountFieldMutationStrategy());

    // Phase 3: Advanced AFL strategies
    strategies.add(new HavocMutationStrategy());

    // Add splicing strategy with corpus access
    if (corpusProvider != null && corpusProvider.getInputCount() >= 2) {
      strategies.add(new SplicingMutationStrategy(corpusProvider));
    }

    return new CombinedMutationStrategy(strategies);
  }

  /**
   * Creates a combined strategy with the given strategies.
   *
   * @param strategies the list of strategies
   */
  public CombinedMutationStrategy(final List<MutationStrategy> strategies) {
    this.strategies = new ArrayList<>(strategies);
    this.weights = new int[strategies.size()];
    int total = 0;
    for (int i = 0; i < strategies.size(); i++) {
      weights[i] = strategies.get(i).weight();
      total += weights[i];
    }
    this.totalWeight = total;
    this.rng = new Random();
  }

  @Override
  public String name() {
    return "combined";
  }

  @Override
  public String description() {
    return "Randomly selects from multiple mutation strategies";
  }

  @Override
  public int weight() {
    return 1;
  }

  @Override
  public MutationResult mutate(final byte[] data) throws MutationException {
    if (strategies.isEmpty()) {
      throw new MutationException("No strategies configured");
    }

    // Select strategy by weight
    int r = rng.nextInt(totalWeight);
    int cumulative = 0;
    MutationStrategy selected = null;

    for (int i = 0; i < strategies.size(); i++) {
      cumulative += weights[i];
      if (r < cumulative) {
        selected = strategies.get(i);
        break;
      }
    }

    if (selected == null) {
      selected = strategies.get(0); // Fallback
    }

    lastSelectedStrategy = selected.name();

    // Try the selected strategy, fall back to others on failure
    List<MutationException> errors = new ArrayList<>();

    try {
      MutationResult result = selected.mutate(data);
      return new MutationResult(result.getData(), selected.name() + ":" + result.getDescription());
    } catch (MutationException e) {
      errors.add(e);
    }

    // Try other strategies if the selected one failed
    for (MutationStrategy strategy : strategies) {
      if (strategy == selected) {
        continue;
      }
      try {
        MutationResult result = strategy.mutate(data);
        lastSelectedStrategy = strategy.name();
        return new MutationResult(
            result.getData(), strategy.name() + ":" + result.getDescription());
      } catch (MutationException e) {
        errors.add(e);
      }
    }

    // All strategies failed
    throw new MutationException(
        "All strategies failed. First error: " + errors.get(0).getMessage());
  }

  /** Returns the name of the last selected strategy. */
  public String getLastSelectedStrategy() {
    return lastSelectedStrategy;
  }

  /** Returns the list of strategies. */
  public List<MutationStrategy> getStrategies() {
    return new ArrayList<>(strategies);
  }
}
