/*
 * Copyright contributors to Besu.
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
package org.hyperledger.besu.evm.operation;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.evm.Code;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.AmsterdamGasCalculator;
import org.hyperledger.besu.evm.testutils.TestMessageFrameBuilder;
import org.hyperledger.besu.evm.toy.ToyWorld;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

class CallCodeOperationTest {

  private static final Address SELF = Address.fromHexString("0xca11ec0b");
  private static final Address BLS_G1ADD_PRECOMPILE = Address.fromHexString("0x0b");
  private static final long NEW_ACCOUNT_STATE_GAS = 120L * 1530L;

  private final ToyWorld toyWorld = new ToyWorld();
  private final AmsterdamGasCalculator gasCalculator = new AmsterdamGasCalculator();

  private MessageFrame parentFrame(final long spilledStateGas) {
    toyWorld.createAccount(SELF, 1, Wei.of(1000));
    final MessageFrame frame =
        new TestMessageFrameBuilder()
            .worldUpdater(toyWorld)
            .initialGas(1_000_000L)
            .address(SELF)
            .contract(SELF)
            .sender(SELF)
            .build();
    frame.setStateGasReservoir(0L);
    frame.incrementStateGasSpilled(spilledStateGas);
    // CALLCODE consumes 7 stack items on completion
    for (int i = 0; i < 7; i++) {
      frame.pushStackItem(Bytes.EMPTY);
    }
    return frame;
  }

  private MessageFrame failedChildFrame(
      final MessageFrame parent, final Address recipient, final Address contract) {
    final MessageFrame child =
        MessageFrame.builder()
            .parentMessageFrame(parent)
            .type(MessageFrame.Type.MESSAGE_CALL)
            .initialGas(0L)
            .address(recipient)
            .contract(contract)
            .inputData(Bytes.EMPTY)
            .sender(parent.getRecipientAddress())
            .value(Wei.ONE)
            .apparentValue(Wei.ONE)
            .code(Code.EMPTY_CODE)
            .isStatic(false)
            .completer(f -> {})
            .build();
    child.setState(MessageFrame.State.COMPLETED_FAILED);
    return child;
  }

  /**
   * EIP-8037 regression: a failed CALLCODE with value to an empty code address (e.g. a precompile)
   * must not refund NEW_ACCOUNT state gas. The charge in execute() keys on the transfer recipient
   * (the caller itself for CALLCODE), which exists, so nothing was charged — a refund keyed on the
   * empty code address would mint gas out of thin air (consensus bug found by fuzzing a BLS12
   * G1ADD CALLCODE at Amsterdam).
   */
  @Test
  void failedCallCodeToPrecompileWithValueDoesNotRefundNewAccountStateGas() {
    final MessageFrame parent = parentFrame(200_000L);
    // CALLCODE: recipient is the caller itself, contract is the (empty) precompile address
    final MessageFrame child = failedChildFrame(parent, SELF, BLS_G1ADD_PRECOMPILE);

    final long gasBefore = parent.getRemainingGas();
    final long reservoirBefore = parent.getStateGasReservoir();

    new CallCodeOperation(gasCalculator).complete(parent, child);

    // Only the child's remaining gas (0) is returned; no phantom state-gas refund.
    assertThat(parent.getRemainingGas()).isEqualTo(gasBefore);
    assertThat(parent.getStateGasReservoir()).isEqualTo(reservoirBefore);
    assertThat(parent.getStateGasSpilled()).isEqualTo(200_000L);
  }

  /**
   * The converse must keep working: a failed CALL with value to a new (empty) recipient was
   * charged NEW_ACCOUNT state gas in execute(), so completion refunds it (routed to remaining gas
   * up to the frame's spilled amount).
   */
  @Test
  void failedCallToNewAccountWithValueRefundsNewAccountStateGas() {
    final MessageFrame parent = parentFrame(200_000L);
    final Address emptyRecipient = Address.fromHexString("0xdead");
    // CALL: recipient == contract == the empty target account
    final MessageFrame child = failedChildFrame(parent, emptyRecipient, emptyRecipient);

    final long gasBefore = parent.getRemainingGas();

    new CallOperation(gasCalculator).complete(parent, child);

    assertThat(parent.getRemainingGas()).isEqualTo(gasBefore + NEW_ACCOUNT_STATE_GAS);
    assertThat(parent.getStateGasSpilled()).isEqualTo(200_000L - NEW_ACCOUNT_STATE_GAS);
  }
}
