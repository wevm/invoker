// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Auth} from "./Auth.sol";

/// @title Generalized EIP-3074 invoker with batch transaction support.
/// @author jxom
/// @notice Use this contract to execute a batch of calls on behalf of an authority.
/// @custom:experimental This is an experimental contract.
contract Invoker is Auth {
    struct Batch {
        address from;
        Call[] calls;
    }

    /// @notice Executes a batch of calls on behalf of the authority, provided a signature that
    ///         was signed by the authority.
    ///
    /// @param batch The batch of calls to execute.
    /// @param signature The signature of the auth message signed by the authority.
    function execute(Batch calldata batch, Signature calldata signature) external payable {
        auth(batch.from, getCommit(batch), signature);

        bytes memory calls;
        for (uint256 i = 0; i < batch.calls.length; i++) {
            calls = abi.encodePacked(
                calls,
                batch.calls[i].to,
                batch.calls[i].value,
                batch.calls[i].data.length,
                batch.calls[i].data
            );
        }

        executeCalls(calls);
    }

    /// @notice Computes the commit of a batch.
    ///
    /// @param batch The batch of calls.
    ///
    /// @return commit The commit of the batch.
    function getCommit(Batch calldata batch) public pure returns (bytes32 commit) {
        return keccak256(abi.encode(batch));
    }

    /// @notice Computes the hash of the auth message of a batch.
    ///
    /// @param batch The batch of calls.
    /// @param nonce The nonce of the authority.
    ///
    /// @return hash The hash of the auth message.
    function getAuthMessageHash(Batch calldata batch, uint256 nonce) external view returns (bytes32) {
        return getAuthMessageHash(getCommit(batch), nonce);
    }

    // Adapted from https://github.com/safe-global/safe-contracts/blob/main/contracts/libraries/MultiSendCallOnly.sol
    function executeCalls(bytes memory calls) internal {
        assembly {
            let length := mload(calls)
            let i := 0x20
            for {
                // Pre block is not used in "while mode"
            } lt(i, length) {
                // Post block is not used in "while mode"
            } {
                // shift by 96 bits (256 - 160 [20 address bytes]) to right-align the data and zero out unused data.
                let to := shr(0x60, mload(add(calls, i)))
                // offset by 20 address bytes
                let value := mload(add(calls, add(i, 0x14)))
                // offset by 52 bytes (20 address bytes + 32 value bytes)
                let dataLength := mload(add(calls, add(i, 0x34)))
                // offset by 84 bytes (20 address bytes + 32 value bytes + 32 data length bytes)
                let data := add(calls, add(i, 0x54))
                let success := authcall(gas(), to, value, 0, data, dataLength, 0, 0)
                if eq(success, 0) {
                    let errorLength := returndatasize()
                    returndatacopy(0, 0, errorLength)
                    revert(0, errorLength)
                }
                // Next entry starts at 84 byte + data length
                i := add(i, add(0x54, dataLength))
            }
        }
    }
}
