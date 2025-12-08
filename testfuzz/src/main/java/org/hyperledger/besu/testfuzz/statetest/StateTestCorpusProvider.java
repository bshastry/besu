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

import java.util.Collections;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Corpus provider implementation for state test fuzzing. Wraps a list of corpus entries and
 * provides random access for splicing mutations.
 *
 * <p>Thread Safety: This implementation is thread-safe for concurrent read access. The underlying
 * corpus list is wrapped as unmodifiable to prevent accidental modification. Workers only read from
 * the corpus - they never write to it.
 *
 * <p>Note: The byte[] arrays returned by getRandomInput() should be treated as read-only or cloned
 * before modification to avoid corrupting the corpus.
 */
public class StateTestCorpusProvider implements SplicingMutationStrategy.CorpusProvider {

  private final List<byte[]> corpus;
  private final int size; // Cached size for thread-safety

  /**
   * Creates a new StateTestCorpusProvider wrapping the given corpus. The corpus list is wrapped as
   * unmodifiable to ensure thread-safety.
   *
   * @param corpus the list of corpus entries (JSON byte arrays)
   */
  public StateTestCorpusProvider(final List<byte[]> corpus) {
    // Wrap as unmodifiable to enforce read-only access from workers
    this.corpus = Collections.unmodifiableList(corpus);
    this.size = corpus.size();
  }

  @Override
  public byte[] getRandomInput() throws MutationStrategy.MutationException {
    if (size == 0) {
      throw new MutationStrategy.MutationException("Corpus is empty");
    }
    // Use cached size to avoid TOCTOU race (size can't change for unmodifiable list)
    int idx = ThreadLocalRandom.current().nextInt(size);
    return corpus.get(idx);
  }

  @Override
  public int getInputCount() {
    return size;
  }
}
