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

/**
 * Interface for state test mutation strategies.
 * Ported from goevmlab's mutation framework.
 */
public interface MutationStrategy {

  /**
   * Returns the name of this mutation strategy.
   *
   * @return the strategy name
   */
  String name();

  /**
   * Returns a description of what this strategy mutates.
   *
   * @return the strategy description
   */
  String description();

  /**
   * Performs mutation on raw JSON test data.
   *
   * @param data the original JSON bytes
   * @return mutation result containing the mutated data
   * @throws MutationException if mutation fails
   */
  MutationResult mutate(final byte[] data) throws MutationException;

  /**
   * Returns the weight for this strategy in combined selection.
   * Higher weights mean more frequent selection.
   *
   * @return the strategy weight
   */
  int weight();

  /**
   * Exception thrown when mutation cannot be performed.
   */
  class MutationException extends Exception {
    /**
     * Creates a new MutationException with a message.
     *
     * @param message the exception message
     */
    public MutationException(final String message) {
      super(message);
    }

    /**
     * Creates a new MutationException with a message and cause.
     *
     * @param message the exception message
     * @param cause the cause of this exception
     */
    public MutationException(final String message, final Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Result of a mutation operation.
   */
  class MutationResult {
    private final byte[] data;
    private final String description;

    /**
     * Creates a new MutationResult.
     *
     * @param data the mutated data
     * @param description description of the mutation
     */
    public MutationResult(final byte[] data, final String description) {
      this.data = data;
      this.description = description;
    }

    /**
     * Returns the mutated data.
     *
     * @return the data
     */
    public byte[] getData() {
      return data;
    }

    /**
     * Returns the mutation description.
     *
     * @return the description
     */
    public String getDescription() {
      return description;
    }
  }
}
