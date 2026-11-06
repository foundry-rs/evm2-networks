# evm2-networks

[evm2](https://github.com/alloy-rs/evm2) execution type families for non-Ethereum networks, intended for integration with [Foundry](https://github.com/foundry-rs/foundry).
These Rust libraries supply network-specific transaction handling, hardfork configuration, and precompiles on top of evm2.
They are not officially maintained by Tempo.

## Crates

- [`op-evm2`](crates/op) - OP Stack execution, including deposits, L1 data fees, and operator fees.
- [`base-evm2`](crates/base) - Base execution, including deposits, native precompiles, and EIP-8130 transactions.
- [`monad-evm2`](crates/monad) - Monad execution, including gas rules, staking, and reserve-balance tracking.

## License

Licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
