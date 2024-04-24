// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {Auth} from "../src/Auth.sol";
import {Invoker} from "../src/Invoker.sol";
import {vToYParity} from "./utils.sol";

contract Example {
    error UnexpectedSender(address expected, address actual);

    mapping(address => uint256) public counter;
    mapping(address => uint256) public values;

    function increment() public payable {
        counter[msg.sender] += 1;
        values[msg.sender] += msg.value;
    }

    function expectSender(address expected) public payable {
        if (msg.sender != expected) {
            revert UnexpectedSender(expected, msg.sender);
        }
    }
}

contract InvokerTest is Test {
    Invoker public invoker;
    Example public example;
    VmSafe.Wallet public sender;
    VmSafe.Wallet public recipient;

    uint8 authcall = 2;

    function setUp() public {
        invoker = new Invoker();
        example = new Example();
        sender = vm.createWallet("sender");
        recipient = vm.createWallet("recipient");
        vm.label(address(invoker), "invoker");
        vm.label(sender.addr, "sender");
        vm.label(recipient.addr, "recipient");
    }

    function test_execute_data() external {
        bytes memory data = abi.encodeWithSelector(Example.increment.selector);
        bytes memory calls;
        calls = abi.encodePacked(
            authcall,
            address(example),
            uint256(0),
            data.length,
            data
        );
        calls = abi.encodePacked(
            calls,
            authcall,
            address(example),
            uint256(0),
            data.length,
            data
        );
        calls = abi.encodePacked(
            calls,
            authcall,
            address(example),
            uint256(0),
            data.length,
            data
        );

        bytes32 hash = invoker.getAuthMessageHash(calls, sender.addr, vm.getNonce(address(sender.addr)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sender.privateKey, hash);
        invoker.execute(calls, sender.addr, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(example.counter(sender.addr), 3);
        assertEq(example.values(sender.addr), 0);
    }

    function test_execute_value() external {
        vm.deal(sender.addr, 1 ether);

        bytes memory calls;
        calls = abi.encodePacked(
            authcall,
            recipient.addr,
            uint256(0.5 ether),
            uint256(0)
        );
        calls = abi.encodePacked(
            calls,
            authcall,
            recipient.addr,
            uint256(0.5 ether),
            uint256(0)
        );

        bytes32 hash = invoker.getAuthMessageHash(calls, sender.addr, vm.getNonce(address(sender.addr)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sender.privateKey, hash);

        invoker.execute(calls, sender.addr, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(address(sender.addr).balance, 0 ether);
        assertEq(address(recipient.addr).balance, 1 ether);
    }

    function test_execute_dataAndValue() external {
        vm.deal(sender.addr, 6 ether);

        bytes memory data = abi.encodeWithSelector(Example.increment.selector);
        bytes memory calls;
        calls = abi.encodePacked(
            authcall,
            address(example),
            uint256(1 ether),
            data.length,
            data
        );
        calls = abi.encodePacked(
            calls,
            authcall,
            address(example),
            uint256(2 ether),
            data.length,
            data
        );
        calls = abi.encodePacked(
            calls,
            authcall,
            address(example),
            uint256(3 ether),
            data.length,
            data
        );

        bytes32 hash = invoker.getAuthMessageHash(calls, sender.addr, vm.getNonce(address(sender.addr)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sender.privateKey, hash);
        invoker.execute(calls, sender.addr, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(example.counter(sender.addr), 3);
        assertEq(example.values(sender.addr), 6 ether);
    }

    function test_execute_revert_invalidSender() external {
        bytes memory data_1 = abi.encodeWithSelector(Example.increment.selector);
        bytes memory data_2 = abi.encodeWithSelector(Example.expectSender.selector, address(0));

        bytes memory calls;
        calls = abi.encodePacked(
            authcall,
            address(example),
            uint256(0),
            data_1.length,
            data_1
        );
        calls = abi.encodePacked(
            calls,
            authcall,
            address(example),
            uint256(0),
            data_2.length,
            data_2
        );

        bytes32 hash = invoker.getAuthMessageHash(calls, sender.addr, vm.getNonce(address(sender.addr)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sender.privateKey, hash);

        vm.expectRevert(abi.encodeWithSelector(Example.UnexpectedSender.selector, address(0), address(sender.addr)));
        invoker.execute(calls, sender.addr, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(example.counter(sender.addr), 0);
    }

    function test_execute_revert_invalidAuthority() external {
        vm.deal(sender.addr, 1 ether);
        vm.deal(recipient.addr, 1 ether);

        bytes memory calls;
        calls = abi.encodePacked(
            authcall,
            recipient.addr,
            uint256(0.5 ether),
            uint256(0)
        );
        calls = abi.encodePacked(
            calls,
            authcall,
            recipient.addr,
            uint256(0.5 ether),
            uint256(0)
        );

        bytes32 hash = invoker.getAuthMessageHash(calls, sender.addr, vm.getNonce(address(sender.addr)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sender.privateKey, hash);

        vm.expectRevert(Auth.InvalidAuthArguments.selector);
        invoker.execute(calls, recipient.addr, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(address(sender.addr).balance, 1 ether);
        assertEq(address(recipient.addr).balance, 1 ether);
    }

    function test_execute_revert_invalidSignature() external {
        vm.deal(sender.addr, 1 ether);
        vm.deal(recipient.addr, 1 ether);

        bytes memory calls;
        calls = abi.encodePacked(
            authcall,
            recipient.addr,
            uint256(0.5 ether),
            uint256(0)
        );
        calls = abi.encodePacked(
            calls,
            authcall,
            recipient.addr,
            uint256(0.5 ether),
            uint256(0)
        );


        VmSafe.Wallet memory badGuy = vm.createWallet("badGuy");
        bytes memory calls_fake;
        calls_fake = abi.encodePacked(
            authcall,
            badGuy.addr,
            uint256(0.5 ether),
            uint256(0)
        );
        calls_fake = abi.encodePacked(
            calls_fake,
            authcall,
            badGuy.addr,
            uint256(0.5 ether),
            uint256(0)
        );

        bytes32 hash = invoker.getAuthMessageHash(calls, sender.addr, vm.getNonce(address(sender.addr)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sender.privateKey, hash);

        vm.expectRevert(Auth.InvalidAuthArguments.selector);
        invoker.execute(calls_fake, sender.addr, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(address(sender.addr).balance, 1 ether);
        assertEq(address(recipient.addr).balance, 1 ether);
    }

    function test_execute_revert_revoke() external {
        vm.deal(sender.addr, 1 ether);

        bytes memory calls;
        calls = abi.encodePacked(
            authcall,
            recipient.addr,
            uint256(0.5 ether),
            uint256(0)
        );
        calls = abi.encodePacked(
            calls,
            authcall,
            recipient.addr,
            uint256(0.5 ether),
            uint256(0)
        );

        bytes32 hash = invoker.getAuthMessageHash(calls, sender.addr, vm.getNonce(address(sender.addr)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sender.privateKey, hash);

        invoker.execute(calls, sender.addr, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(address(sender.addr).balance, 0 ether);
        assertEq(address(recipient.addr).balance, 1 ether);

        // revoke by setting nonce
        vm.setNonce(address(sender.addr), vm.getNonce(address(sender.addr)) + 1);

        vm.expectRevert(Auth.InvalidAuthArguments.selector);
        invoker.execute(calls, sender.addr, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(address(sender.addr).balance, 0 ether);
        assertEq(address(recipient.addr).balance, 1 ether);
    }

    function test_execute_revert_invalidNonce() external {
        vm.deal(sender.addr, 1 ether);

        bytes memory calls;
        calls = abi.encodePacked(
            authcall,
            recipient.addr,
            uint256(0.5 ether),
            uint256(0)
        );
        calls = abi.encodePacked(
            calls,
            authcall,
            recipient.addr,
            uint256(0.5 ether),
            uint256(0)
        );

        bytes32 hash = invoker.getAuthMessageHash(calls, sender.addr, vm.getNonce(address(sender.addr)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sender.privateKey, hash);

        invoker.execute(calls, sender.addr, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(address(sender.addr).balance, 0 ether);
        assertEq(address(recipient.addr).balance, 1 ether);

        vm.expectRevert(Auth.InvalidAuthArguments.selector);
        invoker.execute(calls, sender.addr, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(address(sender.addr).balance, 0 ether);
        assertEq(address(recipient.addr).balance, 1 ether);
    }
}
