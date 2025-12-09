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
package org.hyperledger.besu.testfuzz.tracing;

import org.hyperledger.besu.crypto.MessageDigestFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.tuweni.bytes.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Normalizes EVM traces to a canonical format for cross-VM comparison. This implementation matches
 * geth's normalizer.go exactly to produce identical MD5 hashes.
 *
 * <p>Key normalization rules:
 *
 * <ul>
 *   <li>Filter depth=0 entries (not real opcodes)
 *   <li>Filter STOP opcodes (op=0x00)
 *   <li>Skip duplicate lines with same (pc, depth, functionDepth)
 *   <li>Stack: last 6 items only, lowercase hex, minimal representation (no leading zeros)
 *   <li>Include stateRoot as final line before hash finalization
 * </ul>
 *
 * <p>Optionally accepts a {@link DumpTraceWriter} to output trace lines for debugging divergences.
 */
public class TraceNormalizer {

  private static final Logger LOG = LoggerFactory.getLogger(TraceNormalizer.class);

  private final MessageDigest md5;
  private final DumpTraceWriter dumpWriter;
  private int lineCount;
  private CanonicalOpLog prev; // For duplicate line detection

  /** Creates a new TraceNormalizer. */
  public TraceNormalizer() {
    this(null);
  }

  /**
   * Creates a new TraceNormalizer with optional dump writer.
   *
   * @param dumpWriter optional writer for dumping trace lines (may be null)
   */
  public TraceNormalizer(final DumpTraceWriter dumpWriter) {
    try {
      this.md5 = MessageDigestFactory.create("MD5");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("MD5 algorithm not available", e);
    }
    this.dumpWriter = dumpWriter;
    this.lineCount = 0;
    this.prev = null;
  }

  /**
   * Process a single trace log entry. Applies filtering and writes normalized output to MD5 hasher.
   *
   * @param log the canonical op log entry
   */
  public void processLog(final CanonicalOpLog log) {
    // Filter 1: depth=0 means not a real opcode
    if (log.getDepth() == 0) {
      writeFiltered(DumpTraceWriter.FilterReason.DEPTH_ZERO, log);
      return;
    }

    // Filter 2: STOP opcodes (geth continues on virtual STOP at end of code)
    if (log.getOp() == 0x00) {
      writeFiltered(DumpTraceWriter.FilterReason.STOP_OPCODE, log);
      return;
    }

    // Filter 3: Skip duplicate lines with same (pc, depth, functionDepth)
    if (prev != null
        && prev.getPc() == log.getPc()
        && prev.getDepth() == log.getDepth()
        && prev.getFunctionDepth() == log.getFunctionDepth()) {
      writeFiltered(DumpTraceWriter.FilterReason.DUPLICATE, log);
      return; // Skip duplicate
    }

    // Write previous line (if any) and store current as new prev
    if (prev != null) {
      writeNormalized(prev);
    }
    prev = log;
  }

  /**
   * Writes a filtered entry to the dump writer (if present).
   *
   * @param reason the filter reason
   * @param log the filtered log entry
   */
  private void writeFiltered(final DumpTraceWriter.FilterReason reason, final CanonicalOpLog log) {
    if (dumpWriter != null) {
      try {
        dumpWriter.writeFiltered(reason, log);
      } catch (IOException e) {
        LOG.warn("Failed to write filtered entry to dump file", e);
      }
    }
  }

  /**
   * Finish processing and return the MD5 hash. This flushes any pending log entry and adds the
   * stateRoot as the final line.
   *
   * @param stateRoot the post-execution state root (0x prefixed hex)
   * @return the MD5 hash bytes
   */
  public byte[] finish(final String stateRoot) {
    // Flush pending log entry
    if (prev != null) {
      writeNormalized(prev);
      prev = null;
    }

    // Write stateRoot as final line: {"stateRoot":"0x..."}
    String rootLine = "{\"stateRoot\":\"" + stateRoot + "\"}";
    md5.update(rootLine.getBytes(StandardCharsets.UTF_8));
    md5.update((byte) '\n');
    lineCount++;

    // Write state root to dump file
    if (dumpWriter != null) {
      try {
        dumpWriter.writeStateRoot(stateRoot);
      } catch (IOException e) {
        LOG.warn("Failed to write state root to dump file", e);
      }
    }

    byte[] hash = md5.digest();

    // Write result footer to dump file
    if (dumpWriter != null) {
      try {
        String hashHex = bytesToHex(hash);
        dumpWriter.writeResult(hashHex, lineCount);
      } catch (IOException e) {
        LOG.warn("Failed to write result to dump file", e);
      }
    }

    return hash;
  }

  /**
   * Converts bytes to lowercase hex string.
   *
   * @param bytes the bytes
   * @return lowercase hex string
   */
  private static String bytesToHex(final byte[] bytes) {
    StringBuilder hex = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      hex.append(String.format("%02x", b & 0xFF));
    }
    return hex.toString();
  }

  /**
   * Gets the number of lines processed.
   *
   * @return the line count
   */
  public int getLineCount() {
    return lineCount;
  }

  /** Resets the normalizer for reuse. */
  public void reset() {
    md5.reset();
    lineCount = 0;
    prev = null;
  }

  /**
   * Gets the dump writer (if any).
   *
   * @return the dump writer, or null if none
   */
  public DumpTraceWriter getDumpWriter() {
    return dumpWriter;
  }

  /**
   * Writes a normalized log entry to the MD5 hasher.
   *
   * @param log the log entry
   */
  private void writeNormalized(final CanonicalOpLog log) {
    byte[] data = canonicalMarshal(log);
    md5.update(data);
    md5.update((byte) '\n');
    lineCount++;

    // Also write to dump file if present
    if (dumpWriter != null) {
      try {
        dumpWriter.writeTraceLine(log);
      } catch (IOException e) {
        LOG.warn("Failed to write trace line to dump file", e);
      }
    }
  }

  /**
   * Opcode name lookup table matching geth's opCodeToString. This ensures cross-VM trace
   * compatibility by using identical opcode names.
   */
  private static final Map<Integer, String> OPCODE_NAMES = new HashMap<>();

  static {
    // Stop and Arithmetic Operations
    OPCODE_NAMES.put(0x00, "STOP");
    OPCODE_NAMES.put(0x01, "ADD");
    OPCODE_NAMES.put(0x02, "MUL");
    OPCODE_NAMES.put(0x03, "SUB");
    OPCODE_NAMES.put(0x04, "DIV");
    OPCODE_NAMES.put(0x05, "SDIV");
    OPCODE_NAMES.put(0x06, "MOD");
    OPCODE_NAMES.put(0x07, "SMOD");
    OPCODE_NAMES.put(0x08, "ADDMOD");
    OPCODE_NAMES.put(0x09, "MULMOD");
    OPCODE_NAMES.put(0x0a, "EXP");
    OPCODE_NAMES.put(0x0b, "SIGNEXTEND");

    // Comparison & Bitwise Logic Operations
    OPCODE_NAMES.put(0x10, "LT");
    OPCODE_NAMES.put(0x11, "GT");
    OPCODE_NAMES.put(0x12, "SLT");
    OPCODE_NAMES.put(0x13, "SGT");
    OPCODE_NAMES.put(0x14, "EQ");
    OPCODE_NAMES.put(0x15, "ISZERO");
    OPCODE_NAMES.put(0x16, "AND");
    OPCODE_NAMES.put(0x17, "OR");
    OPCODE_NAMES.put(0x18, "XOR");
    OPCODE_NAMES.put(0x19, "NOT");
    OPCODE_NAMES.put(0x1a, "BYTE");
    OPCODE_NAMES.put(0x1b, "SHL");
    OPCODE_NAMES.put(0x1c, "SHR");
    OPCODE_NAMES.put(0x1d, "SAR");
    OPCODE_NAMES.put(0x1e, "CLZ"); // EIP-7939: Count Leading Zeros (Osaka/Fusaka)

    // SHA3
    OPCODE_NAMES.put(0x20, "KECCAK256");

    // Environmental Information
    OPCODE_NAMES.put(0x30, "ADDRESS");
    OPCODE_NAMES.put(0x31, "BALANCE");
    OPCODE_NAMES.put(0x32, "ORIGIN");
    OPCODE_NAMES.put(0x33, "CALLER");
    OPCODE_NAMES.put(0x34, "CALLVALUE");
    OPCODE_NAMES.put(0x35, "CALLDATALOAD");
    OPCODE_NAMES.put(0x36, "CALLDATASIZE");
    OPCODE_NAMES.put(0x37, "CALLDATACOPY");
    OPCODE_NAMES.put(0x38, "CODESIZE");
    OPCODE_NAMES.put(0x39, "CODECOPY");
    OPCODE_NAMES.put(0x3a, "GASPRICE");
    OPCODE_NAMES.put(0x3b, "EXTCODESIZE");
    OPCODE_NAMES.put(0x3c, "EXTCODECOPY");
    OPCODE_NAMES.put(0x3d, "RETURNDATASIZE");
    OPCODE_NAMES.put(0x3e, "RETURNDATACOPY");
    OPCODE_NAMES.put(0x3f, "EXTCODEHASH");

    // Block Information
    OPCODE_NAMES.put(0x40, "BLOCKHASH");
    OPCODE_NAMES.put(0x41, "COINBASE");
    OPCODE_NAMES.put(0x42, "TIMESTAMP");
    OPCODE_NAMES.put(0x43, "NUMBER");
    OPCODE_NAMES.put(0x44, "DIFFICULTY"); // Geth uses DIFFICULTY for trace compatibility
    OPCODE_NAMES.put(0x45, "GASLIMIT");
    OPCODE_NAMES.put(0x46, "CHAINID");
    OPCODE_NAMES.put(0x47, "SELFBALANCE");
    OPCODE_NAMES.put(0x48, "BASEFEE");
    OPCODE_NAMES.put(0x49, "BLOBHASH");
    OPCODE_NAMES.put(0x4a, "BLOBBASEFEE");

    // Stack, Memory, Storage and Flow Operations
    OPCODE_NAMES.put(0x50, "POP");
    OPCODE_NAMES.put(0x51, "MLOAD");
    OPCODE_NAMES.put(0x52, "MSTORE");
    OPCODE_NAMES.put(0x53, "MSTORE8");
    OPCODE_NAMES.put(0x54, "SLOAD");
    OPCODE_NAMES.put(0x55, "SSTORE");
    OPCODE_NAMES.put(0x56, "JUMP");
    OPCODE_NAMES.put(0x57, "JUMPI");
    OPCODE_NAMES.put(0x58, "PC");
    OPCODE_NAMES.put(0x59, "MSIZE");
    OPCODE_NAMES.put(0x5a, "GAS");
    OPCODE_NAMES.put(0x5b, "JUMPDEST");
    OPCODE_NAMES.put(0x5c, "TLOAD");
    OPCODE_NAMES.put(0x5d, "TSTORE");
    OPCODE_NAMES.put(0x5e, "MCOPY");
    OPCODE_NAMES.put(0x5f, "PUSH0");

    // Push Operations
    OPCODE_NAMES.put(0x60, "PUSH1");
    OPCODE_NAMES.put(0x61, "PUSH2");
    OPCODE_NAMES.put(0x62, "PUSH3");
    OPCODE_NAMES.put(0x63, "PUSH4");
    OPCODE_NAMES.put(0x64, "PUSH5");
    OPCODE_NAMES.put(0x65, "PUSH6");
    OPCODE_NAMES.put(0x66, "PUSH7");
    OPCODE_NAMES.put(0x67, "PUSH8");
    OPCODE_NAMES.put(0x68, "PUSH9");
    OPCODE_NAMES.put(0x69, "PUSH10");
    OPCODE_NAMES.put(0x6a, "PUSH11");
    OPCODE_NAMES.put(0x6b, "PUSH12");
    OPCODE_NAMES.put(0x6c, "PUSH13");
    OPCODE_NAMES.put(0x6d, "PUSH14");
    OPCODE_NAMES.put(0x6e, "PUSH15");
    OPCODE_NAMES.put(0x6f, "PUSH16");
    OPCODE_NAMES.put(0x70, "PUSH17");
    OPCODE_NAMES.put(0x71, "PUSH18");
    OPCODE_NAMES.put(0x72, "PUSH19");
    OPCODE_NAMES.put(0x73, "PUSH20");
    OPCODE_NAMES.put(0x74, "PUSH21");
    OPCODE_NAMES.put(0x75, "PUSH22");
    OPCODE_NAMES.put(0x76, "PUSH23");
    OPCODE_NAMES.put(0x77, "PUSH24");
    OPCODE_NAMES.put(0x78, "PUSH25");
    OPCODE_NAMES.put(0x79, "PUSH26");
    OPCODE_NAMES.put(0x7a, "PUSH27");
    OPCODE_NAMES.put(0x7b, "PUSH28");
    OPCODE_NAMES.put(0x7c, "PUSH29");
    OPCODE_NAMES.put(0x7d, "PUSH30");
    OPCODE_NAMES.put(0x7e, "PUSH31");
    OPCODE_NAMES.put(0x7f, "PUSH32");

    // Duplication Operations
    OPCODE_NAMES.put(0x80, "DUP1");
    OPCODE_NAMES.put(0x81, "DUP2");
    OPCODE_NAMES.put(0x82, "DUP3");
    OPCODE_NAMES.put(0x83, "DUP4");
    OPCODE_NAMES.put(0x84, "DUP5");
    OPCODE_NAMES.put(0x85, "DUP6");
    OPCODE_NAMES.put(0x86, "DUP7");
    OPCODE_NAMES.put(0x87, "DUP8");
    OPCODE_NAMES.put(0x88, "DUP9");
    OPCODE_NAMES.put(0x89, "DUP10");
    OPCODE_NAMES.put(0x8a, "DUP11");
    OPCODE_NAMES.put(0x8b, "DUP12");
    OPCODE_NAMES.put(0x8c, "DUP13");
    OPCODE_NAMES.put(0x8d, "DUP14");
    OPCODE_NAMES.put(0x8e, "DUP15");
    OPCODE_NAMES.put(0x8f, "DUP16");

    // Exchange Operations
    OPCODE_NAMES.put(0x90, "SWAP1");
    OPCODE_NAMES.put(0x91, "SWAP2");
    OPCODE_NAMES.put(0x92, "SWAP3");
    OPCODE_NAMES.put(0x93, "SWAP4");
    OPCODE_NAMES.put(0x94, "SWAP5");
    OPCODE_NAMES.put(0x95, "SWAP6");
    OPCODE_NAMES.put(0x96, "SWAP7");
    OPCODE_NAMES.put(0x97, "SWAP8");
    OPCODE_NAMES.put(0x98, "SWAP9");
    OPCODE_NAMES.put(0x99, "SWAP10");
    OPCODE_NAMES.put(0x9a, "SWAP11");
    OPCODE_NAMES.put(0x9b, "SWAP12");
    OPCODE_NAMES.put(0x9c, "SWAP13");
    OPCODE_NAMES.put(0x9d, "SWAP14");
    OPCODE_NAMES.put(0x9e, "SWAP15");
    OPCODE_NAMES.put(0x9f, "SWAP16");

    // Logging Operations
    OPCODE_NAMES.put(0xa0, "LOG0");
    OPCODE_NAMES.put(0xa1, "LOG1");
    OPCODE_NAMES.put(0xa2, "LOG2");
    OPCODE_NAMES.put(0xa3, "LOG3");
    OPCODE_NAMES.put(0xa4, "LOG4");

    // EOF Data Operations (EIP-7480)
    OPCODE_NAMES.put(0xd0, "DATALOAD");
    OPCODE_NAMES.put(0xd1, "DATALOADN");
    OPCODE_NAMES.put(0xd2, "DATASIZE");
    OPCODE_NAMES.put(0xd3, "DATACOPY");

    // EOF Control Flow Operations (EIP-4750, EIP-6206, EIP-663)
    OPCODE_NAMES.put(0xe0, "RJUMP");
    OPCODE_NAMES.put(0xe1, "RJUMPI");
    OPCODE_NAMES.put(0xe2, "RJUMPV");
    OPCODE_NAMES.put(0xe3, "CALLF");
    OPCODE_NAMES.put(0xe4, "RETF");
    OPCODE_NAMES.put(0xe5, "JUMPF");
    OPCODE_NAMES.put(0xe6, "DUPN");
    OPCODE_NAMES.put(0xe7, "SWAPN");
    OPCODE_NAMES.put(0xe8, "EXCHANGE");
    OPCODE_NAMES.put(0xec, "EOFCREATE");
    OPCODE_NAMES.put(0xee, "RETURNCONTRACT");

    // System Operations
    OPCODE_NAMES.put(0xf0, "CREATE");
    OPCODE_NAMES.put(0xf1, "CALL");
    OPCODE_NAMES.put(0xf2, "CALLCODE");
    OPCODE_NAMES.put(0xf3, "RETURN");
    OPCODE_NAMES.put(0xf4, "DELEGATECALL");
    OPCODE_NAMES.put(0xf5, "CREATE2");
    OPCODE_NAMES.put(0xf7, "RETURNDATALOAD");
    OPCODE_NAMES.put(0xf8, "EXTCALL");
    OPCODE_NAMES.put(0xf9, "EXTDELEGATECALL");
    OPCODE_NAMES.put(0xfa, "STATICCALL");
    OPCODE_NAMES.put(0xfb, "EXTSTATICCALL");
    OPCODE_NAMES.put(0xfd, "REVERT");
    OPCODE_NAMES.put(0xfe, "INVALID");
    OPCODE_NAMES.put(0xff, "SELFDESTRUCT");
  }

  /**
   * Derives the opcode name from the opcode byte, matching geth's vm.OpCode(op).String() behavior.
   * For defined opcodes, returns the standard name. For undefined opcodes, returns "opcode 0x%x not
   * defined" format (matching geth's fmt.Sprintf("opcode %#x not defined", int(op))).
   *
   * @param op the opcode byte
   * @return the opcode name matching geth's format
   */
  public static String deriveOpName(final int op) {
    int opcode = op & 0xFF;
    String name = OPCODE_NAMES.get(opcode);
    if (name != null) {
      return name;
    }
    // Match geth's format: "opcode 0xd not defined" (lowercase hex, no leading zero)
    return String.format("opcode 0x%x not defined", opcode);
  }

  /**
   * Produces deterministic JSON output for an oplog. Field order must match geth exactly: depth,
   * pc, [section], [functionDepth], gas, op, opName, stack
   *
   * @param log the log entry
   * @return the canonical JSON bytes
   */
  public static byte[] canonicalMarshal(final CanonicalOpLog log) {
    StringBuilder b = new StringBuilder(256);

    // depth (always, decimal)
    b.append("{\"depth\":");
    b.append(log.getDepth());

    // pc (always, decimal)
    b.append(",\"pc\":");
    b.append(log.getPc());

    // section (only if non-zero, EOF)
    if (log.getSection() != 0) {
      b.append(",\"section\":");
      b.append(log.getSection());
    }

    // functionDepth (only if non-zero, EOF)
    if (log.getFunctionDepth() != 0) {
      b.append(",\"functionDepth\":");
      b.append(log.getFunctionDepth());
    }

    // gas (always, decimal)
    b.append(",\"gas\":");
    b.append(log.getGas());

    // op (hex, 0x-prefixed, 2 digits, zero-padded)
    b.append(",\"op\":\"0x");
    int op = log.getOp() & 0xFF;
    if (op < 0x10) {
      b.append('0');
    }
    b.append(Integer.toHexString(op));
    b.append('"');

    // opName (always) - derive from opcode to match geth's vm.OpCode(op).String()
    b.append(",\"opName\":\"");
    b.append(deriveOpName(op));
    b.append('"');

    // stack (array of hex strings, last 6 items, lowercase, minimal representation)
    b.append(",\"stack\":[");
    List<Bytes> stack = log.getStack();
    if (stack != null && !stack.isEmpty()) {
      for (int i = 0; i < stack.size(); i++) {
        if (i > 0) {
          b.append(',');
        }
        b.append('"');
        b.append(formatStackItem(stack.get(i)));
        b.append('"');
      }
    }
    b.append(']');

    b.append('}');
    return b.toString().getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Formats a stack item as lowercase hex with minimal representation (no leading zeros). Must
   * match geth's uint256.Int.Hex() output exactly.
   *
   * <p>Examples: 0x0, 0xf, 0xff, 0xdeadbeef (not 0x00, 0x0f, 0x00ff)
   *
   * @param item the stack item (may be null)
   * @return the formatted hex string
   */
  public static String formatStackItem(final Bytes item) {
    if (item == null || item.isEmpty()) {
      return "0x0";
    }

    // Find first non-zero byte
    int start = 0;
    while (start < item.size() && item.get(start) == 0) {
      start++;
    }

    if (start == item.size()) {
      return "0x0"; // All zeros
    }

    // Build hex string without leading zeros
    StringBuilder hex = new StringBuilder("0x");
    boolean firstByte = true;
    for (int i = start; i < item.size(); i++) {
      int b = item.get(i) & 0xFF;
      if (firstByte) {
        // First byte: don't pad with leading zero if < 0x10
        if (b < 0x10 && b > 0) {
          hex.append(Integer.toHexString(b));
        } else {
          hex.append(String.format("%02x", b));
        }
        firstByte = false;
      } else {
        // Subsequent bytes: always 2 digits
        hex.append(String.format("%02x", b));
      }
    }

    return hex.toString();
  }
}
