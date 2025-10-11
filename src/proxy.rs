// proxy.rs
use bytes::Bytes;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use http_body_util::{Either, Empty};
use hyper::{
    body::Incoming, client::conn::http1 as client_http1, server::conn::http1 as server_http1,
    service::service_fn, Method, Request, Response,
};
use hyper_util::rt::TokioIo;
use rand::Rng;
use std::{
    error::Error as StdError,
    fmt,
    io::{self, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpSocket, TcpStream},
};

type ProxyResult<T> = Result<T, ProxyError>;
type ProxyBody = Either<Empty<Bytes>, Incoming>;

#[derive(Debug)]
enum ProxyError {
    Hyper(hyper::Error),
    Io(io::Error),
    Message(&'static str),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::Hyper(err) => write!(f, "hyper error: {err}"),
            ProxyError::Io(err) => write!(f, "io error: {err}"),
            ProxyError::Message(msg) => write!(f, "{msg}"),
        }
    }
}

impl StdError for ProxyError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ProxyError::Hyper(err) => Some(err),
            ProxyError::Io(err) => Some(err),
            ProxyError::Message(_) => None,
        }
    }
}

impl From<hyper::Error> for ProxyError {
    fn from(err: hyper::Error) -> Self {
        ProxyError::Hyper(err)
    }
}

impl From<io::Error> for ProxyError {
    fn from(err: io::Error) -> Self {
        ProxyError::Io(err)
    }
}

impl From<&'static str> for ProxyError {
    fn from(msg: &'static str) -> Self {
        ProxyError::Message(msg)
    }
}

#[derive(Clone, Default)]
pub struct ProxyConfig {
    pub ipv6: Option<Ipv6Cidr>,
    pub ipv4: Option<Ipv4Cidr>,
}

pub async fn start_proxy(
    listen_addr: SocketAddr,
    config: ProxyConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen_addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let config_clone = config.clone();

        tokio::task::spawn(async move {
            let proxy = Proxy {
                config: config_clone,
            };
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let proxy = proxy.clone();
                async move { proxy.proxy(req).await }
            });

            if let Err(err) = server_http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                eprintln!("connection error: {err}");
            }
        });
    }
}

#[derive(Clone)]
pub(crate) struct Proxy {
    pub config: ProxyConfig,
}

impl Proxy {
    async fn proxy(self, req: Request<Incoming>) -> ProxyResult<Response<ProxyBody>> {
        if req.method() == Method::CONNECT {
            self.process_connect(req).await
        } else {
            self.process_request(req).await
        }
    }

    async fn process_connect(self, req: Request<Incoming>) -> ProxyResult<Response<ProxyBody>> {
        tokio::task::spawn(async move {
            let remote_addr = req.uri().authority().map(|auth| auth.to_string()).unwrap();
            let upgraded = hyper::upgrade::on(req).await.unwrap();
            let mut upgraded = TokioIo::new(upgraded);
            if let Err(err) = self.tunnel(&mut upgraded, remote_addr).await {
                eprintln!("tunnel error: {err}");
            }
        });
        Ok(Response::new(Either::Left(Empty::<Bytes>::new())))
    }

    async fn process_request(self, req: Request<Incoming>) -> ProxyResult<Response<ProxyBody>> {
        let authority = req
            .uri()
            .authority()
            .ok_or("request missing authority")?
            .clone();
        let host = authority.host().to_string();
        let port = authority
            .port_u16()
            .unwrap_or_else(|| match req.uri().scheme_str() {
                Some("https") => 443,
                _ => 80,
            });

        let stream = self.connect_to_host(&host, port).await?;
        if let Ok(addr) = stream.local_addr() {
            println!("{} via {}", host, addr.ip());
        } else {
            println!("{host} via <unknown>");
        }

        let io = TokioIo::new(stream);
        let (mut sender, connection) = client_http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(io)
            .await?;

        tokio::task::spawn(async move {
            if let Err(err) = connection.without_shutdown().await {
                eprintln!("upstream connection error: {err}");
            }
        });

        let res = sender.send_request(req).await?;
        let (parts, body) = res.into_parts();
        Ok(Response::from_parts(parts, Either::Right(body)))
    }

    async fn tunnel<A>(self, upgraded: &mut A, addr_str: String) -> io::Result<()>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        if let Ok(addrs) = addr_str.to_socket_addrs() {
            for addr in addrs {
                let socket = match addr {
                    SocketAddr::V4(_) => TcpSocket::new_v4()?,
                    SocketAddr::V6(_) => TcpSocket::new_v6()?,
                };
                let bind_addr = match self.get_rand_socket_addr_for(&addr) {
                    Some(addr) => addr,
                    None => continue,
                };
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

    async fn connect_to_host(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let addrs = tokio::net::lookup_host((host, port)).await?;
        self.connect_to_first(addrs).await
    }

    async fn connect_to_first<I>(&self, addrs: I) -> io::Result<TcpStream>
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        let mut last_err = None;
        let mut attempted = false;

        for addr in addrs {
            let socket = match addr {
                SocketAddr::V4(_) => TcpSocket::new_v4()?,
                SocketAddr::V6(_) => TcpSocket::new_v6()?,
            };

            let bind_addr = match self.get_rand_socket_addr_for(&addr) {
                Some(addr) => addr,
                None => continue,
            };

            attempted = true;

            if let Err(err) = socket.bind(bind_addr) {
                last_err = Some(err);
                continue;
            }

            match socket.connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }

        if !attempted {
            return Err(io::Error::new(
                ErrorKind::AddrNotAvailable,
                "no available address family for destination",
            ));
        }

        Err(last_err.unwrap_or_else(|| {
            io::Error::new(ErrorKind::Other, "unable to connect to destination")
        }))
    }

    fn get_rand_socket_addr_for(&self, remote: &SocketAddr) -> Option<SocketAddr> {
        match remote {
            SocketAddr::V4(_) => self
                .config
                .ipv4
                .as_ref()
                .map(|_| SocketAddr::new(IpAddr::V4(self.get_rand_ipv4()), 0)),
            SocketAddr::V6(_) => self
                .config
                .ipv6
                .as_ref()
                .map(|_| SocketAddr::new(IpAddr::V6(self.get_rand_ipv6()), 0)),
        }
    }

    fn get_rand_ipv6(&self) -> Ipv6Addr {
        if let Some(ipv6_cidr) = self.config.ipv6 {
            let len = ipv6_cidr.network_length();
            ipv6_cidr
                .iter()
                .nth(rand::thread_rng().gen_range(0..(1 << (128 - len))))
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
                .nth(rand::thread_rng().gen_range(0..(1 << (32 - len))))
                .unwrap()
                .address()
        } else {
            panic!("IPv4 subnet not configured")
        }
    }
}
