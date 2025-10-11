// main.rs
mod proxy;

use cidr::{Ipv4Cidr, Ipv6Cidr};
use getopts::Options;
use proxy::{start_proxy, ProxyConfig};
use std::{env, process::exit};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("b", "bind", "http proxy bind address", "BIND");
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
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("{}", f.to_string())
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
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

    let bind_addr = matches.opt_str("b").unwrap_or("0.0.0.0:51080".to_string());
    let ipv6_subnet = matches.opt_str("6");
    let ipv4_subnet = matches.opt_str("4");
    run(bind_addr, ipv6_subnet, ipv4_subnet)
}

#[tokio::main]
async fn run(bind_addr: String, ipv6_subnet: Option<String>, ipv4_subnet: Option<String>) {
    let mut config = ProxyConfig::default();

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

    let bind_addr = match bind_addr.parse() {
        Ok(b) => b,
        Err(e) => {
            println!("Bind address not valid: {}", e);
            return;
        }
    };

    if let Err(e) = start_proxy(bind_addr, config).await {
        println!("{}", e);
    }
}
