# Operating Procedures

## Tech Stack
- Language: Rust 2021 edition, stable toolchain
- Testing: cargo test (unit, integration, adversarial)
- Build: cargo build --release

## Standards
- No unsafe code
- All errors handled — no unwrap() on user input paths
- Exit code always 0 in hook mode
- Policy evaluation deterministic and side-effect-free

## Verification
- cargo test must pass all existing 128 tests
- New features need integration tests in tests/integration_cli.rs
- No task is done until tests pass

## Preferences
- Prefer editing existing files over creating new ones
- Keep changes minimal and focused
- Follow existing code patterns in main.rs for CLI output style
