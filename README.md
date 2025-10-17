# An HTTP & SOCKS proxy

[<img alt="github" src="https://img.shields.io/badge/github-xxxbrian%2Ffluxy-8da0cb?style=for-the-badge&logo=github" height="24">
](https://github.com/xxxbrian/fluxy)
[<img alt="crates.io" src="https://img.shields.io/crates/v/fluxy?style=for-the-badge&color=fc8d62&logo=rust" height="24">
](https://crates.io/crates/fluxy)
[<img alt="license" src="https://img.shields.io/crates/l/fluxy?style=for-the-badge&color=4285f4" height="24">
](https://choosealicense.com/licenses/mit)

**Command-Line Options**

`-H, --http-bind HTTP_BIND`
Bind the HTTP proxy on the provided address.

`-S, --socks-bind SOCKS_BIND`
Bind the SOCKS5 proxy on the provided address.

`-4, --ipv4-subnet IPV4_SUBNET`
Define an IPv4 subnet in CIDR notation (e.g., 192.168.0.0/24).

`-6, --ipv6-subnet IPV6_SUBNET`
Define an IPv6 subnet in CIDR notation (e.g., 2001:db8::/32).

`-h, --help`
Display the help menu.

`-v, --version`
Print the current build version.

`--log LEVEL`
Set the logging level: `trace`, `debug`, `info`, `warn`, `error` (default: `info`).

At least one of `--http-bind`/`-H` or `--socks-bind`/`-S` must be provided.
