# Examples

Each example is runnable and prints what it demonstrates. Features are noted per
example; the first needs none.

| Example | Run with | Shows |
|---------|----------|-------|
| `01_quickstart` | *(no features)* | Building events, integrity metadata, JSON-lines output |
| `02_tamper_evident` | `--features hmac-chain` | Four attacks on a signed log, and what detection looks like |
| `03_levels_and_filtering` | `--features hmac-chain` | Level thresholds and the two-tier admission policy |
| `04_tracing_bridge` | `--features "tracing hmac-chain"` | Routing `tracing` logs into a tamper-evident chain |
| `05_provenance` | `--features hmac-chain` | Recording *and proving* where an event came from |
| `06_service_end_to_end` | `--features hmac-chain` | Writing a log file, then verifying it with the CLI |
| `07_concurrent_logging` | `--features hmac-chain` | Why multi-threaded logs need `--unordered` |
| `08_macros` | `--features hmac-chain` | Every macro: `ash_logger!`, the five levels, and `ash_audit!` |
| `09_causal_ordering` | `--features "hlc hmac-chain"` | Monotonic timestamps, and carrying order across services |
| `10_production_setup` | `--features hmac-chain` | Rotating file, async writer, redaction, scopes, live filtering |

```bash
cargo run --example 01_quickstart
cargo run --features hmac-chain --example 02_tamper_evident
cargo run --features "tracing hmac-chain" --example 04_tracing_bridge
```

## Where to start

- **New to the crate:** `01_quickstart`, then `03_levels_and_filtering`.
- **Writing calling code:** `08_macros` is the shorthand you will actually type.
- **Deploying for real:** `10_production_setup` is the configuration to copy.
- **Evaluating tamper evidence:** `02_tamper_evident` is the one to read. It runs
  the attacks rather than describing them, including the re-stamping attack that
  defeats an unkeyed checksum.
- **Replacing an existing logger:** `04_tracing_bridge`.
- **Deploying:** `06_service_end_to_end` writes a real file and prints the exact
  verification commands, and `07_concurrent_logging` covers the one operational
  gotcha worth knowing before you rely on the verifier in CI.

## A note on keys

The examples embed a literal key so they run without setup. Never do this in
production: load the key from a KMS, a secrets manager, or an environment
variable, use at least 32 random bytes, and never write it to the log it
protects. See [SECURITY.md](../SECURITY.md).
