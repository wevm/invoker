// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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

    function getAuthMessageHash(uint256 nonce, bytes32 commit) public view returns (bytes32) {
        bytes32 chainId = bytes32(block.chainid);
        bytes32 invokerAddress = bytes32(uint256(uint160(address(this))));
        return keccak256(abi.encodePacked(MAGIC, chainId, nonce, invokerAddress, commit));
    }

    function auth(address authority, bytes32 commit, Signature memory signature) public returns (bool success) {
        bytes memory args = abi.encodePacked(signature.yParity, signature.r, signature.s, commit);
        assembly {
            success := auth(authority, add(args, 0x20), mload(args))
        }
        if (!success) revert InvalidAuthArguments();
    }

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
