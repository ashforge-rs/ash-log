# Contributing to ash-log

## Getting started

```bash
git clone https://github.com/ashforge-rs/ash-log.git
cd ash-log
make ci
```

`make ci` runs everything the CI pipeline does: format check, clippy, the full
feature matrix of tests, and a documentation build with warnings denied. If it
passes locally, CI should pass too.

## Before opening a pull request

```bash
make fmt   # cargo fmt --all
make ci    # must pass
```

## Commit messages

Commits follow [Conventional Commits](https://www.conventionalcommits.org/) and
are linted in CI. Allowed types are `feat`, `fix`, `docs`, `style`, `refactor`,
`perf`, `test`, `build`, `ci`, `chore`, and `revert`.

```
feat(integrity): add HmacChainIntegrity for tamper-evident logs
fix(backends): flush buffered events on drop
docs: clarify truncation limits of the hash chain
```

Keep the subject under 100 characters, lower-case, with no trailing period.

## Feature flags

The crate must build and pass tests with **every** combination of features, not
just `--all-features`. `make test-matrix` checks each one; CI does the same.

Anything requiring the `hmac` or `sha2` dependencies belongs behind
`hmac-chain`, and anything requiring the OCSF schema behind `ocsf`.

## Testing expectations

New code needs tests at the appropriate level:

- **Unit tests** beside the module, in a `#[cfg(test)] mod tests`.
- **Integration tests** in `tests/` when the behaviour is part of the public
  API contract.
- **CLI tests** in `tests/cli_verify.rs` for anything affecting `ash-log-verify`,
  asserting on exit codes rather than only on output text.

Security-relevant changes need a test that models the actual attack. When adding
an integrity mechanism, show that a tampered log fails to verify — an assertion
that a clean log passes proves very little on its own.

## Security-sensitive changes

Integrity mechanisms and anything touching the HMAC chain warrant extra care:

- Never log, print, or serialize the key.
- Any data included in a MAC must be covered by a canonical, deterministic
  encoding — if two equal events can produce different bytes, verification
  becomes flaky; if two different events can produce the same bytes, the
  mechanism is broken.
- Compare MACs in constant time.
- Document new limitations in both the rustdoc and `SECURITY.md`.

To report a vulnerability, follow [SECURITY.md](SECURITY.md) rather than opening
a public issue.

## Documentation

`#![deny(missing_docs)]` is enabled, so every public item needs a doc comment.
Documentation builds with `-D warnings` in CI, which makes a broken intra-doc
link a build failure. Public API changes should update the README as well.

## License

Contributions are licensed under Apache-2.0, matching the project.
