// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Auth} from "./Auth.sol";

/// @title Generalized EIP-3074 invoker with batch transaction support.
/// @author jxom
/// @notice Use this contract to execute a batch of calls on behalf of an authority.
/// @custom:experimental This is an experimental contract.
contract Invoker is Auth {
    /// @notice Nonces of the authorities.
    mapping(address => uint256) public nonces;

    /// @notice Executes calls on behalf of the authority, provided a signature that
    ///         was signed by the authority.
    ///
    /// @param calls Calls to execute in format of packed bytes of:
    ///              `operation` (uint8): operation type – must equal uint8(2) for AUTHCALL.
    ///              `to` (address): address of the recipient.
    ///              `value` (uint256): value in wei to send.
    ///              `dataLength` (uint256): length of the data.
    ///              `data` (bytes): calldata to send.
    /// @param authority The authority to execute the calls on behalf of.
    /// @param signature The signature of the auth message signed by the authority.
    function execute(bytes calldata calls, address authority, Signature calldata signature) external payable {
        auth(authority, getCommit(calls, authority), signature);
        nonces[authority]++;
        executeCalls(calls);
    }

    /// @notice Computes the commit of a batch.
    ///
    /// @param calls Calls to execute in format of packed bytes of:
    ///              `operation` (uint8): operation type – must equal uint8(2) for AUTHCALL.
    ///              `to` (address): address of the recipient.
    ///              `value` (uint256): value in wei to send.
    ///              `dataLength` (uint256): length of the data.
    ///              `data` (bytes): calldata to send.
    /// @param authority The authority to execute the calls on behalf of.
    ///
    /// @return commit The commit of the batch.
    function getCommit(bytes calldata calls, address authority) public view returns (bytes32 commit) {
        return keccak256(abi.encodePacked(calls, nonces[authority]));
    }

    /// @notice Computes the hash of the auth message of a batch.
    ///
    /// @param calls Calls to execute in format of packed bytes of:
    ///              `operation` (uint8): operation type – must equal uint8(2) for AUTHCALL.
    ///              `to` (address): address of the recipient.
    ///              `value` (uint256): value in wei to send.
    ///              `dataLength` (uint256): length of the data.
    ///              `data` (bytes): calldata to send.
    /// @param authority The authority to execute the calls on behalf of.
    /// @param nonce The nonce of the authority.
    ///
    /// @return hash The hash of the auth message.
    function getAuthMessageHash(bytes calldata calls, address authority, uint256 nonce) external view returns (bytes32) {
        return getAuthMessageHash(getCommit(calls, authority), nonce);
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
