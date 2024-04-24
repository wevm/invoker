// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Auth} from "./Auth.sol";
import {AbstractInvoker} from "./AbstractInvoker.sol";
import {BatchExecutor} from "./BatchExecutor.sol";

/// @title Invoker with batch call support & replay protection.
/// @author jxom
/// @notice Use this contract to execute a batch of calls on behalf of an authority.
/// @custom:experimental This is an experimental contract.
contract Invoker is AbstractInvoker, BatchExecutor {
    /// @notice Nonces of the authorities.
    mapping(address => uint256) public nonces;

    /// @notice Computes the commit of a batch.
    ///
    /// @param data Calls to execute in format of packed bytes of:
    ///              `operation` (uint8): operation type – must equal uint8(2) for AUTHCALL.
    ///              `to` (address): address of the recipient.
    ///              `value` (uint256): value in wei to send.
    ///              `dataLength` (uint256): length of the data.
    ///              `data` (bytes): calldata to send.
    /// @param authority The authority to execute the calls on behalf of.
    ///
    /// @return commit The commit of the batch.
    function getCommit(bytes calldata data, address authority) override public view returns (bytes32 commit) {
        return keccak256(abi.encodePacked(data, nonces[authority]));
    }

    /// @notice Executes calls on behalf of the authority, provided a signature that
    ///         was signed by the authority.
    ///
    /// @param data Calls to execute in format of packed bytes of:
    ///              `operation` (uint8): operation type – must equal uint8(2) for AUTHCALL.
    ///              `to` (address): address of the recipient.
    ///              `value` (uint256): value in wei to send.
    ///              `dataLength` (uint256): length of the data.
    ///              `data` (bytes): calldata to send.
    /// @param authority The authority to execute the calls on behalf of.
    function exec(bytes calldata data, address authority) override internal {
        nonces[authority]++;
        executeCalls(data);
    }
}
