# Changelog

## v0.3.2
- Added SOCKS5 UDP ASSOCIATE support so datagrams reuse the IP pool just like TCP connections.
- Wrapped fast-socks5 UDP handling with a custom transfer that binds sockets via `socket2` and emits per-datagram tracing, improving observability.
- Simplified local IP selection logic and resolved clippy warnings.

## v0.3.1
- Introduced structured tracing with per-connection IDs and a configurable `--log` level for both HTTP and SOCKS services.
- Updated documentation to describe the new logging workflow and removed the old `--verbose` wording.
- Cleaned up clippy findings after the logging refactor.

## v0.3.0
- Added SOCKS5 proxy support alongside the HTTP proxy, sharing the outbound connector.
- Reworked the CLI so HTTP and SOCKS listeners can be bound independently via `--http-bind/-H` and `--socks-bind/-S`.
- Documented the new SOCKS features and command-line options.

## v0.2.2
- Swapped `rand` for `fastrand`, reducing dependency size while keeping random IP generation fast.
- Hardened HTTP CONNECT handling by returning 400 when the authority is missing and logging upgrade errors.
- Improved CLI error reporting when argument parsing fails.

## v0.2.1
- Added a `--verbose` flag (later superseded) and related README notes to make log levels adjustable.
- Optimised HTTP proxy plumbing by letting the OS choose ephemeral ports and using `Either` for response bodies.
- Expanded the CI workflow to publish GitHub releases across multiple targets and kept the codebase clippy-clean.

## v0.2.0
- Migrated to hyper 1.x and refactored the proxy implementation to match the new API surface.

## v0.1.2
- Added a `--version` flag to print package metadata on demand.
- Broadened `.gitignore`, refreshed dependencies, and tightened the release profile for better optimised builds.

## v0.1.1
- Initial HTTP proxy release with CIDR-driven random IP binding.
- Added repository metadata, license, README (with badges), and fixed the IP selection range bug.
