# fluxy

> High-performance HTTP & SOCKS5 proxy that rotates outbound addresses from configurable IPv4/IPv6 pools.

[<img alt="github" src="https://img.shields.io/badge/github-xxxbrian%2Ffluxy-8da0cb?style=for-the-badge&logo=github" height="24">
](https://github.com/xxxbrian/fluxy)
[<img alt="crates.io" src="https://img.shields.io/crates/v/fluxy?style=for-the-badge&color=fc8d62&logo=rust" height="24">
](https://crates.io/crates/fluxy)
[<img alt="license" src="https://img.shields.io/crates/l/fluxy?style=for-the-badge&color=4285f4" height="24">
](https://choosealicense.com/licenses/mit)

## Features
- **HTTP CONNECT proxy** with full request forwarding.
- **SOCKS5 proxy** supporting TCP `CONNECT` and UDP `ASSOCIATE`.
- **Address pool randomisation**: each outbound connection or datagram binds to a random IP drawn from the subnets you provide (`-4` / `-6`).
- **Structured tracing** with per-connection IDs, pluggable log levels, and consistent formatting.
- Async, Tokio-based architecture tuned for low overhead.

## Installation

```bash
cargo install fluxy
```

Build from source:

```bash
git clone https://github.com/xxxbrian/fluxy.git
cd fluxy
cargo build --release
```

The release binary will be available at `target/release/fluxy`.

Pre-built archives for popular targets are published on the [GitHub Releases](https://github.com/xxxbrian/fluxy/releases) page.

## Usage

```bash
fluxy \
  --http-bind 127.0.0.1:6152 \
  --socks-bind 127.0.0.1:6153 \
  --ipv4-subnet 44.31.223.0/24 \
  --ipv6-subnet 2a0e:aa07:e0a0::/48 \
  --log debug
```

### CLI flags

| Flag | Description |
| ---- | ----------- |
| `-H`, `--http-bind <ADDR>` | Listen address for the HTTP proxy. |
| `-S`, `--socks-bind <ADDR>` | Listen address for the SOCKS5 proxy. |
| `-4`, `--ipv4-subnet <CIDR>` | IPv4 subnet used for outbound socket binding (optional). |
| `-6`, `--ipv6-subnet <CIDR>` | IPv6 subnet used for outbound socket binding (optional). |
| `--log <LEVEL>` | Log level (`trace`, `debug`, `info`, `warn`, `error`). Defaults to `info`. |
| `-v`, `--version` | Print version information and exit. |
| `-h`, `--help` | Show the help text. |

> Supply at least one of `--http-bind` or `--socks-bind`. Supplying both runs both proxies concurrently.

### Preparing address pools

Fluxy binds every outbound socket to a random address within the subnets you configure. These source addresses must be routable on your host. For local testing (or when operating as a BGP player with many announced prefixes), assign the pool or a subset of addresses to a loopback/VRF interface before starting the proxy:

```bash
# Linux
sudo ip addr add 44.31.223.0/24 dev lo

# macOS
sudo ifconfig lo0 alias 44.31.223.0 255.255.255.0
```

## License

MIT © [Bojin Li](https://github.com/xxxbrian)
