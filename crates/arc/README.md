# arc-evm2

[Arc](https://www.arc.network)'s execution type family for [evm2](https://github.com/alloy-rs/evm2).

This crate ports the single-transaction execution rules of arc-node (`circlefin/arc-node` v0.8.6,
crates `arc-evm`, `arc-precompiles` and `arc-execution-config`) to evm2. On Arc, USDC is the native
gas token, exposed as an ERC-20 at `0x3600…0000` whose balances live in native account balances.

- [`ArcHardfork`] (`Zero3` to `Zero8`) and [`ArcSpecId`], which pairs the active Arc hardfork with
  the Ethereum specification it runs on (Prague, then Osaka). [`arc_spec_at`] resolves both for
  Arc mainnet (`5042`) and testnet (`5042002`) at a block number and timestamp, and
  [`arc_spec_at_timestamp`] from the timestamp alone, which only mislabels testnet block 11172018
  (it shares Zero3's activation second; Zero3 to Zero6 change no execution rule in arc-node v0.8.6).
- [`ArcEvmTypes`] is the evm2 type family. Arc's runtime version ([`arc_version`]) enables EIP-7708
  `Transfer` logs on every hardfork, and its opcode table ([`arc_opcode_config`]) replaces `CALL`,
  `CREATE`, `CREATE2` and `SELFDESTRUCT`.
- Native transfer rules ([`transfer`]): a value transfer from or to the zero address, from or to a
  blocklisted address, or to an account self-destructed in the same transaction reverts the frame
  before it runs, returning all its gas. The blocklist is the `NativeCoinControl` storage, read
  unmetered.
- `SELFDESTRUCT` of a non-zero balance reverts on the zero address, on the contract itself, on a
  blocklisted beneficiary or contract, and on a self-destructed beneficiary. Blocklist read failures
  are ignored before Zero7 and abort the transaction from Zero7.
- [`ArcTxHandlerHooks`] rejects transactions from a blocklisted sender, or sending value to a
  blocklisted recipient, and credits the whole fee, base fee included, to the beneficiary. From
  Zero8, a self-destructed beneficiary invalidates the transaction.
- [`ArcPrecompiles`] adds Arc's precompiles to the Ethereum set: `NativeCoinAuthority`
  (`0x1800…0000`: mint, burn, transfer, total supply), `NativeCoinControl` (`0x1800…0001`: the
  blocklist), `SystemAccounting` (`0x1800…0002`: per-block gas values), `CallFrom` (`0x1800…0003`,
  from Zero7) and the SLH-DSA-SHA2-128s verifier (`0x1800…0004`). Like arc-node, which resolves
  them lazily, they are not warm at the start of a transaction.
- [`ArcEvmFactory`] builds configured [`ArcEvm`] instances.

## Not covered

- The first frame of a transaction: arc-node reverts a transaction sending value to the zero
  address, or creating a contract with value at a blocklisted address. evm2's standard handlers
  have no hook before the first frame, so these transactions fail validation with
  [`ArcTxError::RejectedTransfer`] instead.
- Block execution: the `SystemAccounting` writes, the base fee computation, the beneficiary
  blocklist check and the EIP-2935 history writes run in arc-node's block executor.
- Before Zero8, arc-node runs out of gas in `SELFDESTRUCT` when its beneficiary is outside the access
  list, even if the transaction already touched it, and less than the cold access cost is left.
  evm2 does not track the access list apart from the transaction's warm accounts, so this crate
  uses the transaction's warmth, as arc-node does from Zero8.
- arc-node's tracing limits (`max_trace_bytes`) and its inspector view of `CallFrom`, which traces
  the subcall as a call from the sender: evm2 traces the precompile call and its child.
- Arc devnet and genesis-configured chains are not resolved by [`arc_spec_at`].
