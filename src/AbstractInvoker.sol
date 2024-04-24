// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Auth} from "./Auth.sol";

/// @title Base Invoker interface & implementation.
/// @author jxom
/// @notice Shared functionality and interfaces for Invoker contracts.
/// @custom:experimental This is an experimental contract.
abstract contract AbstractInvoker is Auth {
    /// @notice Computes the commit of execution data.
    /// @dev This function must be implemented by the invoker implementation.
    function getCommit(bytes calldata data, address authority) virtual public view returns (bytes32 commit);

    /// @notice Executes data on behalf of the authority.
    /// @dev This function must be implemented by the invoker implementation.
    function exec(bytes calldata data, address authority, Signature calldata signature) virtual internal;

    function execute(bytes calldata data, address authority, Signature calldata signature) external payable {
        auth(authority, getCommit(data, authority), signature);
        exec(data, authority, signature);
    }

    /// @notice Computes the hash of the auth message.
    ///
    /// @param data Execution data.
    /// @param authority The authority to execute the data on behalf of.
    /// @param nonce The nonce of the authority.
    ///
    /// @return hash The hash of the auth message.
    function getAuthMessageHash(bytes calldata data, address authority, uint256 nonce) external view returns (bytes32) {
        return getAuthMessageHash(getCommit(data, authority), nonce);
    }
}