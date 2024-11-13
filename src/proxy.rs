// proxy.rs
use cidr::{Ipv4Cidr, Ipv6Cidr};
use hyper::{
    client::HttpConnector,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Client, Method, Request, Response, Server,
};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpSocket,
};

#[derive(Clone, Default)]
pub struct ProxyConfig {
    pub ipv6: Option<Ipv6Cidr>,
    pub ipv4: Option<Ipv4Cidr>,
}

pub async fn start_proxy(
    listen_addr: SocketAddr,
    config: ProxyConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let make_service = make_service_fn(move |_: &AddrStream| {
        let config = config.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let config = config.clone();
                Proxy { config }.proxy(req)
            }))
        }
    });

    Server::bind(&listen_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service)
        .await
        .map_err(|err| err.into())
}

#[derive(Clone)]
pub(crate) struct Proxy {
    pub config: ProxyConfig,
}

impl Proxy {
    pub(crate) async fn proxy(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        match if req.method() == Method::CONNECT {
            self.process_connect(req).await
        } else {
            self.process_request(req).await
        } {
            Ok(resp) => Ok(resp),
            Err(e) => Err(e),
        }
    }

    async fn process_connect(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        tokio::task::spawn(async move {
            let remote_addr = req.uri().authority().map(|auth| auth.to_string()).unwrap();
            let mut upgraded = hyper::upgrade::on(req).await.unwrap();
            self.tunnel(&mut upgraded, remote_addr).await
        });
        Ok(Response::new(Body::empty()))
    }

    async fn process_request(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let bind_addr = self.get_rand_ip();
        let mut http = HttpConnector::new();
        http.set_local_address(Some(bind_addr));
        println!("{} via {bind_addr}", req.uri().host().unwrap_or_default());

        let client = Client::builder()
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build(http);
        let res = client.request(req).await?;
        Ok(res)
    }

    async fn tunnel<A>(self, upgraded: &mut A, addr_str: String) -> std::io::Result<()>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        if let Ok(addrs) = addr_str.to_socket_addrs() {
            for addr in addrs {
                let socket = match addr {
                    SocketAddr::V4(_) => TcpSocket::new_v4()?,
                    SocketAddr::V6(_) => TcpSocket::new_v6()?,
                };
                let bind_addr = self.get_rand_socket_addr();
                if socket.bind(bind_addr).is_ok() {
                    println!("{addr_str} via {bind_addr}");
                    if let Ok(mut server) = socket.connect(addr).await {
                        tokio::io::copy_bidirectional(upgraded, &mut server).await?;
                        return Ok(());
                    }
                }
            }
        } else {
            println!("error: {addr_str}");
        }

        Ok(())
    }

    fn get_rand_ip(&self) -> IpAddr {
        let mut rng = rand::thread_rng();
        if rng.gen_bool(0.5) && self.config.ipv6.is_some() {
            IpAddr::V6(self.get_rand_ipv6())
        } else if self.config.ipv4.is_some() {
            IpAddr::V4(self.get_rand_ipv4())
        } else {
            IpAddr::V6(self.get_rand_ipv6()) // Fallback to IPv6 if IPv4 is not configured
        }
    }

    fn get_rand_socket_addr(&self) -> SocketAddr {
        let ip = self.get_rand_ip();
        let port = rand::thread_rng().gen::<u16>();
        SocketAddr::new(ip, port)
    }

    fn get_rand_ipv6(&self) -> Ipv6Addr {
        if let Some(ipv6_cidr) = self.config.ipv6 {
            let len = ipv6_cidr.network_length();
            ipv6_cidr
                .iter()
                .nth(rand::thread_rng().gen_range(0..len.into()))
                .unwrap()
                .address()
        } else {
            panic!("IPv6 subnet not configured")
        }
    }

    fn get_rand_ipv4(&self) -> Ipv4Addr {
        if let Some(ipv4_cidr) = self.config.ipv4 {
            let len = ipv4_cidr.network_length();
            ipv4_cidr
                .iter()
                .nth(rand::thread_rng().gen_range(0..len.into()))
                .unwrap()
                .address()
        } else {
            panic!("IPv4 subnet not configured")
        }
    }
}
