# EIP-3074 Invoker

Generalized EIP-3074 Invoker with batch transaction support. Inspired by @clabby's work on [`eip-3074-foundry`](https://github.com/clabby/eip-3074-foundry).

> [!WARNING] 
> WIP. Very experimental, not audited, use with caution.

## Patches

This repository contains patches (h/t @clabby) of the following repositories to support EIP-3074 opcodes:

- [`revm`](https://github.com/jxom/revm/tree/jxom/eip-3074)
- [`foundry`](https://github.com/jxom/foundry/tree/jxom/eip-3074)
- [`solc`](https://github.com/clabby/solidity/tree/cl/eip-3074)

## Installation

```
git submodule update --init --recursive && make
```

## Building Contracts

```
make build
```

## Running Tests

```
make test
```