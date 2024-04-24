// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Auth} from "./Auth.sol";
import {AbstractInvoker} from "./AbstractInvoker.sol";

// Adapted from https://github.com/safe-global/safe-contracts/blob/main/contracts/libraries/MultiSendCallOnly.sol
contract BatchExecutor {
    function executeCalls(bytes memory calls) public payable {
        assembly {
            let length := mload(calls)
            let i := 0x20
            for {
                // Pre block is not used in "while mode"
            } lt(i, length) {
                // Post block is not used in "while mode"
            } {
                // First byte of the data is the operation.
                // We shift by 248 bits (256 - 8 [operation byte]) it right since mload will always load 32 bytes (a word).
                // This will also zero out unused data.
                let operation := shr(0xf8, mload(add(calls, i)))
                // We offset the load address by 1 byte (operation byte)
                // We shift it right by 96 bits (256 - 160 [20 address bytes]) to right-align the data and zero out unused data.
                let to := shr(0x60, mload(add(calls, add(i, 0x01))))
                // Defaults `to` to `address(this)` if `address(0)` is provided.
                to := or(to, mul(iszero(to), address()))
                // We offset the load address by 21 byte (operation byte + 20 address bytes)
                let value := mload(add(calls, add(i, 0x15)))
                // We offset the load address by 53 byte (operation byte + 20 address bytes + 32 value bytes)
                let dataLength := mload(add(calls, add(i, 0x35)))
                // We offset the load address by 85 byte (operation byte + 20 address bytes + 32 value bytes + 32 data length bytes)
                let data := add(calls, add(i, 0x55))
                let success := 0
                switch operation
                // This version does not allow regular calls
                case 0 { revert(0, 0) }
                // This version does not allow delegatecalls
                case 1 { revert(0, 0) }
                case 2 { success := authcall(gas(), to, value, 0, data, dataLength, 0, 0) }
                if eq(success, 0) {
                    let errorLength := returndatasize()
                    returndatacopy(0, 0, errorLength)
                    revert(0, errorLength)
                }
                // Next entry starts at 85 byte + data length
                i := add(i, add(0x55, dataLength))
            }
        }
    }
}
