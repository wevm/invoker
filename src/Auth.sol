// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Simple abstraction over the EIP-3074 AUTH and AUTHCALL opcodes.
/// @author jxom
/// @notice Use this contract to authenticate and execute calls with the AUTH and AUTHCALL opcodes, 
///         along with auth message hash computation. 
/// @custom:experimental This is an experimental contract.
contract Auth {
    uint8 constant MAGIC = 0x04;

    error InvalidAuthArguments();

    struct Call {
        bytes data;
        address to;
        uint256 value;
    }

    struct Signature {
        uint8 yParity;
        bytes32 r;
        bytes32 s;
    }

    /// @notice Computes the hash of the auth message, to be signed by the authority.
    ///
    /// @param nonce The nonce of the authority.
    /// @param commit The commit.
    ///
    /// @return hash Keccak256 hash of the auth message.
    function getAuthMessageHash(uint256 nonce, bytes32 commit) public view returns (bytes32) {
        bytes32 chainId = bytes32(block.chainid);
        bytes32 invokerAddress = bytes32(uint256(uint160(address(this))));
        return keccak256(abi.encodePacked(MAGIC, chainId, nonce, invokerAddress, commit));
    }

    /// @notice Authorize the sender to send calls on behalf of the authority.
    ///
    /// @param authority The authority to authorize with.
    /// @param commit The commit.
    /// @param signature The signature of the auth message.
    ///
    /// @return success True if the authorization is successful.
    function auth(address authority, bytes32 commit, Signature memory signature) public returns (bool success) {
        bytes memory args = abi.encodePacked(signature.yParity, signature.r, signature.s, commit);
        assembly {
            success := auth(authority, add(args, 0x20), mload(args))
        }
        if (!success) revert InvalidAuthArguments();
    }

    /// @notice Executes a call on behalf of the authority.
    ///
    /// @param call The call to execute.
    ///
    /// @return success True if the call is successful.
    function authcall(Call calldata call) public returns (bool success) {
        address to = call.to;
        uint256 value = call.value;
        bytes memory data = call.data;

        assembly {
            success := authcall(gas(), to, value, 0, add(data, 0x20), mload(data), 0, 0)
            if iszero(success) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
    }
}
