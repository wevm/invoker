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

    uint256 nonce = 0;
    uint256 value = 0;

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
        Auth.Call[] memory calls = new Auth.Call[](3);
        calls[0] = Auth.Call({to: address(example), value: 0, data: abi.encodeWithSelector(Example.increment.selector)});
        calls[1] = Auth.Call({to: address(example), value: 0, data: abi.encodeWithSelector(Example.increment.selector)});
        calls[2] = Auth.Call({to: address(example), value: 0, data: abi.encodeWithSelector(Example.increment.selector)});

        Invoker.Batch memory batch =
            Invoker.Batch({from: sender.addr, calls: calls});

        bytes32 hash = invoker.getAuthMessageHash(batch, vm.getNonce(address(sender.addr)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sender.privateKey, hash);
        invoker.execute(batch, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(example.counter(sender.addr), 3);
        assertEq(example.values(sender.addr), 0);
    }

    function test_execute_value() external {
        vm.deal(sender.addr, 1 ether);

        Auth.Call[] memory calls = new Auth.Call[](2);
        calls[0] = Auth.Call({to: recipient.addr, value: 0.5 ether, data: "0x"});
        calls[1] = Auth.Call({to: recipient.addr, value: 0.5 ether, data: "0x"});

        Invoker.Batch memory batch = Invoker.Batch({from: sender.addr, calls: calls});

        bytes32 hash = invoker.getAuthMessageHash(batch, vm.getNonce(address(sender.addr)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sender.privateKey, hash);

        invoker.execute(batch, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(address(sender.addr).balance, 0 ether);
        assertEq(address(recipient.addr).balance, 1 ether);
    }

    function test_execute_dataAndValue() external {
        vm.deal(sender.addr, 6 ether);

        Auth.Call[] memory calls = new Auth.Call[](3);
        calls[0] =
            Auth.Call({to: address(example), value: 1 ether, data: abi.encodeWithSelector(Example.increment.selector)});
        calls[1] =
            Auth.Call({to: address(example), value: 2 ether, data: abi.encodeWithSelector(Example.increment.selector)});
        calls[2] =
            Auth.Call({to: address(example), value: 3 ether, data: abi.encodeWithSelector(Example.increment.selector)});

        Invoker.Batch memory batch =
            Invoker.Batch({from: sender.addr, calls: calls});

        bytes32 hash = invoker.getAuthMessageHash(batch, vm.getNonce(address(sender.addr)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sender.privateKey, hash);
        invoker.execute(batch, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(example.counter(sender.addr), 3);
        assertEq(example.values(sender.addr), 6 ether);
    }

    function test_execute_revert_invalidSender() external {
        Auth.Call[] memory calls = new Auth.Call[](3);
        calls[0] = Auth.Call({to: address(example), value: 0, data: abi.encodeWithSelector(Example.increment.selector)});
        calls[1] = Auth.Call({
            to: address(example),
            value: 0,
            data: abi.encodeWithSelector(Example.expectSender.selector, address(0))
        });

        Invoker.Batch memory batch =
            Invoker.Batch({from: sender.addr, calls: calls});

        bytes32 hash = invoker.getAuthMessageHash(batch, vm.getNonce(address(sender.addr)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sender.privateKey, hash);

        vm.expectRevert(abi.encodeWithSelector(Example.UnexpectedSender.selector, address(0), address(sender.addr)));
        invoker.execute(batch, Auth.Signature({yParity: vToYParity(v), r: r, s: s}));

        assertEq(example.counter(sender.addr), 0);
    }
}
