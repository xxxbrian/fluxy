// main.rs
mod proxy;

use cidr::{Ipv4Cidr, Ipv6Cidr};
use getopts::Options;
use proxy::{start_http_proxy, start_socks_proxy, OutboundConnector, ProxyConfig};
use std::{env, net::SocketAddr, process::exit};

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("H", "http-bind", "HTTP proxy bind address", "HTTP_BIND");
    opts.optopt("S", "socks-bind", "SOCKS5 proxy bind address", "SOCKS_BIND");
    opts.optopt(
        "6",
        "ipv6-subnet",
        "IPv6 Subnet: 2001:19f0:6001:48e4::/64",
        "IPv6_SUBNET",
    );
    opts.optopt(
        "4",
        "ipv4-subnet",
        "IPv4 Subnet: 192.168.0.0/24",
        "IPv4_SUBNET",
    );
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("v", "version", "print version information");
    opts.optflag("", "verbose", "enable verbose logging");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            eprintln!("{}: {}", program, f);
            print_usage(&program, &opts);
            return;
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, &opts);
        return;
    }

    if matches.opt_present("v") {
        println!(
            "{} version {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
        return;
    }

    let http_bind = matches
        .opt_str("http-bind")
        .or_else(|| matches.opt_str("H"));
    let socks_bind = matches
        .opt_str("socks-bind")
        .or_else(|| matches.opt_str("S"));

    if http_bind.is_none() && socks_bind.is_none() {
        eprintln!("At least one of --http-bind/-H or --socks-bind/-S must be provided.");
        print_usage(&program, &opts);
        return;
    }

    let ipv6_subnet = matches.opt_str("6");
    let ipv4_subnet = matches.opt_str("4");
    let verbose = matches.opt_present("verbose");
    run(http_bind, socks_bind, ipv6_subnet, ipv4_subnet, verbose)
}

#[tokio::main]
async fn run(
    http_bind: Option<String>,
    socks_bind: Option<String>,
    ipv6_subnet: Option<String>,
    ipv4_subnet: Option<String>,
    verbose: bool,
) {
    if http_bind.is_none() && socks_bind.is_none() {
        eprintln!("No services enabled. Provide --http-bind/-H and/or --socks-bind/-S.");
        return;
    }

    let mut config = ProxyConfig {
        verbose,
        ..ProxyConfig::default()
    };

    if let Some(subnet) = ipv6_subnet {
        match subnet.parse::<Ipv6Cidr>() {
            Ok(cidr) => {
                config.ipv6 = Some(cidr);
            }
            Err(_) => {
                println!("Invalid IPv6 subnet");
                exit(1);
            }
        }
    }

    if let Some(subnet) = ipv4_subnet {
        match subnet.parse::<Ipv4Cidr>() {
            Ok(cidr) => {
                config.ipv4 = Some(cidr);
            }
            Err(_) => {
                println!("Invalid IPv4 subnet");
                exit(1);
            }
        }
    }

    let http_addr = match http_bind {
        Some(bind) => match bind.parse::<SocketAddr>() {
            Ok(addr) => Some(addr),
            Err(e) => {
                println!("HTTP bind address not valid: {}", e);
                return;
            }
        },
        None => None,
    };

    let socks_addr = match socks_bind {
        Some(bind) => match bind.parse::<SocketAddr>() {
            Ok(addr) => Some(addr),
            Err(e) => {
                println!("SOCKS bind address not valid: {}", e);
                return;
            }
        },
        None => None,
    };

    let connector = OutboundConnector::new(config);

    type AnyError = Box<dyn std::error::Error + Send + Sync>;

    match (http_addr, socks_addr) {
        (Some(http_addr), Some(socks_addr)) => {
            let http_connector = connector.clone();
            let socks_connector = connector;

            let http_future = async move {
                start_http_proxy(http_addr, http_connector)
                    .await
                    .map_err(|err| -> AnyError { Box::new(err) })
            };

            let socks_future = async move {
                start_socks_proxy(socks_addr, socks_connector)
                    .await
                    .map_err(|err| -> AnyError { Box::new(err) })
            };

            if let Err(err) = tokio::try_join!(http_future, socks_future) {
                eprintln!("{err}");
            }
        }
        (Some(http_addr), None) => {
            if let Err(err) = start_http_proxy(http_addr, connector).await {
                eprintln!("{err}");
            }
        }
        (None, Some(socks_addr)) => {
            if let Err(err) = start_socks_proxy(socks_addr, connector).await {
                eprintln!("{err}");
            }
        }
        (None, None) => unreachable!(),
    }
}
