use bytes::Bytes;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use fast_socks5::{
    server::{states, transfer, DnsResolveHelper as _, Socks5ServerProtocol, SocksServerError},
    ReplyError, Socks5Command,
};
use http_body_util::{Either, Empty};
use hyper::{
    body::Incoming, client::conn::http1 as client_http1, server::conn::http1 as server_http1,
    service::service_fn, Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
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

#[derive(Clone, Default)]
pub struct ProxyConfig {
    pub ipv6: Option<Ipv6Cidr>,
    pub ipv4: Option<Ipv4Cidr>,
    pub verbose: bool,
}

#[derive(Clone)]
pub struct OutboundConnector {
    config: ProxyConfig,
}

impl OutboundConnector {
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    pub fn log_verbose(&self, message: &str) {
        if self.config.verbose {
            eprintln!("{message}");
        }
    }

    pub async fn connect_host(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let addrs = tokio::net::lookup_host((host, port)).await?;
        self.connect_with_addrs(addrs).await
    }

    pub async fn connect_addr(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        self.connect_with_addrs(std::iter::once(addr)).await
    }

    async fn connect_with_addrs<I>(&self, addrs: I) -> io::Result<TcpStream>
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
        if let Some(ipv6_cidr) = &self.config.ipv6 {
            let host_bits = 128u32 - u32::from(ipv6_cidr.network_length());
            let base = u128::from(ipv6_cidr.first_address());
            let offset = random_host_offset_u128(host_bits);
            Ipv6Addr::from(base | offset)
        } else {
            panic!("IPv6 subnet not configured");
        }
    }

    fn get_rand_ipv4(&self) -> Ipv4Addr {
        if let Some(ipv4_cidr) = &self.config.ipv4 {
            let host_bits = 32u32 - u32::from(ipv4_cidr.network_length());
            let base = u32::from(ipv4_cidr.first_address());
            let offset = random_host_offset_u32(host_bits);
            Ipv4Addr::from(base | offset)
        } else {
            panic!("IPv4 subnet not configured");
        }
    }
}

pub use http::start_http_proxy;
pub use socks::start_socks_proxy;

mod http {
    use super::*;

    type ProxyResult<T> = Result<T, ProxyError>;
    type ProxyBody = Either<Empty<Bytes>, Incoming>;

    pub async fn start_http_proxy(
        listen_addr: SocketAddr,
        connector: OutboundConnector,
    ) -> io::Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;

        loop {
            let (stream, _) = listener.accept().await?;
            let handler = HttpProxy {
                connector: connector.clone(),
            };

            tokio::task::spawn(async move {
                let proxy_for_service = handler.clone();
                let io = TokioIo::new(stream);
                let service = service_fn(move |req| {
                    let proxy = proxy_for_service.clone();
                    async move { proxy.proxy(req).await }
                });

                if let Err(err) = server_http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                {
                    handler.log_verbose(&format!("connection error: {err}"));
                }
            });
        }
    }

    #[derive(Clone)]
    struct HttpProxy {
        connector: OutboundConnector,
    }

    impl HttpProxy {
        async fn proxy(self, req: Request<Incoming>) -> ProxyResult<Response<ProxyBody>> {
            if req.method() == Method::CONNECT {
                self.process_connect(req).await
            } else {
                self.process_request(req).await
            }
        }

        async fn process_connect(self, req: Request<Incoming>) -> ProxyResult<Response<ProxyBody>> {
            let remote_addr = match req.uri().authority().map(|auth| auth.to_string()) {
                Some(addr) => addr,
                None => {
                    let mut response = Response::new(Either::Left(Empty::<Bytes>::new()));
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }
            };

            tokio::task::spawn(async move {
                let proxy = self;
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let mut upgraded = TokioIo::new(upgraded);
                        if let Err(err) = proxy.tunnel(&mut upgraded, remote_addr).await {
                            proxy.log_verbose(&format!("tunnel error: {err}"));
                        }
                    }
                    Err(err) => proxy.log_verbose(&format!("upgrade error: {err}")),
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

            let stream = self.connector.connect_host(&host, port).await?;
            if let Ok(addr) = stream.local_addr() {
                self.log_verbose(&format!("{} via {}", host, addr.ip()));
            } else {
                self.log_verbose(&format!("{host} via <unknown>"));
            }

            let io = TokioIo::new(stream);
            let (mut sender, connection) = client_http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(io)
                .await?;

            let proxy_clone = self.clone();
            tokio::task::spawn(async move {
                if let Err(err) = connection.without_shutdown().await {
                    proxy_clone.log_verbose(&format!("upstream connection error: {err}"));
                }
            });

            let res = sender.send_request(req).await?;
            let (parts, body) = res.into_parts();
            Ok(Response::from_parts(parts, Either::Right(body)))
        }

        async fn tunnel<A>(&self, upgraded: &mut A, addr_str: String) -> io::Result<()>
        where
            A: AsyncRead + AsyncWrite + Unpin + ?Sized,
        {
            if let Ok(addrs) = addr_str.to_socket_addrs() {
                for addr in addrs {
                    if let Ok(mut server) = self.connector.connect_addr(addr).await {
                        if let Ok(local) = server.local_addr() {
                            self.log_verbose(&format!("{addr_str} via {}", local.ip()));
                        }
                        tokio::io::copy_bidirectional(upgraded, &mut server).await?;
                        return Ok(());
                    }
                }
            } else {
                self.log_verbose(&format!("error: {addr_str}"));
            }

            Ok(())
        }

        fn log_verbose(&self, message: &str) {
            self.connector.log_verbose(message);
        }
    }

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
}

mod socks {
    use super::*;
    use fast_socks5::util::target_addr::TargetAddr;

    pub async fn start_socks_proxy(
        listen_addr: SocketAddr,
        connector: OutboundConnector,
    ) -> io::Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;

        loop {
            let (stream, _) = listener.accept().await?;
            let connector_for_task = connector.clone();

            tokio::task::spawn(async move {
                let logger = connector_for_task.clone();
                if let Err(err) = handle_connection(connector_for_task, stream).await {
                    logger.log_verbose(&format!("socks error: {err}"));
                }
            });
        }
    }

    async fn handle_connection(
        connector: OutboundConnector,
        stream: TcpStream,
    ) -> Result<(), SocksProxyError> {
        let proto = Socks5ServerProtocol::accept_no_auth(stream).await?;
        let (proto, cmd, target_addr) = proto.read_command().await?.resolve_dns().await?;

        match cmd {
            Socks5Command::TCPConnect => handle_tcp_connect(connector, proto, target_addr).await,
            _ => {
                proto.reply_error(&ReplyError::CommandNotSupported).await?;
                Ok(())
            }
        }
    }

    async fn handle_tcp_connect<T>(
        connector: OutboundConnector,
        proto: Socks5ServerProtocol<T, states::CommandRead>,
        target_addr: TargetAddr,
    ) -> Result<(), SocksProxyError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let target_display = target_addr.to_string();
        let destination = match target_addr {
            TargetAddr::Ip(addr) => addr,
            TargetAddr::Domain(_, _) => {
                proto.reply_error(&ReplyError::GeneralFailure).await?;
                return Ok(());
            }
        };

        let outbound = match connector.connect_addr(destination).await {
            Ok(stream) => stream,
            Err(err) => {
                let reply = reply_error_for_io(&err);
                proto.reply_error(&reply).await?;
                return Err(err.into());
            }
        };

        let local_addr = match outbound.local_addr() {
            Ok(addr) => {
                connector.log_verbose(&format!("{target_display} via {}", addr.ip()));
                addr
            }
            Err(_) => {
                connector.log_verbose(&format!("{target_display} via <unknown>"));
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            }
        };

        let mut inbound = proto.reply_success(local_addr).await?;
        transfer(&mut inbound, outbound).await;
        Ok(())
    }

    #[derive(Debug)]
    enum SocksProxyError {
        Io(io::Error),
        Protocol(SocksServerError),
    }

    impl fmt::Display for SocksProxyError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                SocksProxyError::Io(err) => write!(f, "io error: {err}"),
                SocksProxyError::Protocol(err) => write!(f, "protocol error: {err}"),
            }
        }
    }

    impl StdError for SocksProxyError {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            match self {
                SocksProxyError::Io(err) => Some(err),
                SocksProxyError::Protocol(err) => Some(err),
            }
        }
    }

    impl From<io::Error> for SocksProxyError {
        fn from(err: io::Error) -> Self {
            SocksProxyError::Io(err)
        }
    }

    impl From<SocksServerError> for SocksProxyError {
        fn from(err: SocksServerError) -> Self {
            SocksProxyError::Protocol(err)
        }
    }

    fn reply_error_for_io(err: &io::Error) -> ReplyError {
        match err.kind() {
            ErrorKind::ConnectionRefused => ReplyError::ConnectionRefused,
            ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset => {
                ReplyError::ConnectionNotAllowed
            }
            ErrorKind::TimedOut => ReplyError::ConnectionTimeout,
            ErrorKind::HostUnreachable => ReplyError::HostUnreachable,
            ErrorKind::NotConnected
            | ErrorKind::AddrNotAvailable
            | ErrorKind::NetworkUnreachable => ReplyError::NetworkUnreachable,
            _ => ReplyError::GeneralFailure,
        }
    }
}

fn random_host_offset_u32(bits: u32) -> u32 {
    match bits {
        0 => 0,
        32 => fastrand::u32(..=u32::MAX),
        b => {
            let mask = (1u32 << b) - 1;
            fastrand::u32(0..=mask)
        }
    }
}

fn random_host_offset_u128(bits: u32) -> u128 {
    match bits {
        0 => 0,
        b if b >= 128 => random_u128(),
        b => {
            let mask = (1u128 << b) - 1;
            random_u128() & mask
        }
    }
}

fn random_u128() -> u128 {
    let high = fastrand::u64(..=u64::MAX) as u128;
    let low = fastrand::u64(..=u64::MAX) as u128;
    (high << 64) | low
}
