use bytes::Bytes;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use fast_socks5::{
    server::{
        run_udp_proxy, states, transfer, DnsResolveHelper as _, Socks5ServerProtocol,
        SocksServerError,
    },
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
use tracing::Instrument;

#[derive(Clone, Default)]
pub struct ProxyConfig {
    pub ipv6: Option<Ipv6Cidr>,
    pub ipv4: Option<Ipv4Cidr>,
}

#[derive(Clone)]
pub struct OutboundConnector {
    config: ProxyConfig,
}

impl OutboundConnector {
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
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

        Err(last_err.unwrap_or_else(|| io::Error::other("unable to connect to destination")))
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

    pub fn random_local_ip_for(&self, remote: IpAddr) -> io::Result<IpAddr> {
        if let IpAddr::V4(ip) = remote {
            if !ip.is_unspecified() {
                if self.config.ipv4.is_some() {
                    return Ok(IpAddr::V4(self.get_rand_ipv4()));
                }
            } else if let Some(_) = self.config.ipv4 {
                return Ok(IpAddr::V4(self.get_rand_ipv4()));
            }
        }

        if let IpAddr::V6(ip) = remote {
            if !ip.is_unspecified() {
                if self.config.ipv6.is_some() {
                    return Ok(IpAddr::V6(self.get_rand_ipv6()));
                }
            } else if let Some(_) = self.config.ipv6 {
                return Ok(IpAddr::V6(self.get_rand_ipv6()));
            }
        }

        // fall back to whichever pool is available if remote is unspecified
        if remote.is_unspecified() {
            if let Some(_) = self.config.ipv4 {
                return Ok(IpAddr::V4(self.get_rand_ipv4()));
            }
            if let Some(_) = self.config.ipv6 {
                return Ok(IpAddr::V6(self.get_rand_ipv6()));
            }
        }

        Err(io::Error::new(
            ErrorKind::AddrNotAvailable,
            "no available address family for destination",
        ))
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
        tracing::info!("HTTP proxy listening on {}", listen_addr);

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
                    tracing::debug!("HTTP connection error: {}", err);
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
            let conn_id = crate::logging::new_conn_id();

            if req.method() == Method::CONNECT {
                let span = tracing::debug_span!("http_connect", conn_id = %conn_id);
                self.process_connect(req).instrument(span).await
            } else {
                let span = tracing::debug_span!("http_request", conn_id = %conn_id);
                self.process_request(req).instrument(span).await
            }
        }

        async fn process_connect(self, req: Request<Incoming>) -> ProxyResult<Response<ProxyBody>> {
            let remote_addr = match req.uri().authority().map(|auth| auth.to_string()) {
                Some(addr) => addr,
                None => {
                    tracing::debug!("invalid CONNECT request");
                    let mut response = Response::new(Either::Left(Empty::<Bytes>::new()));
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }
            };

            tracing::debug!("CONNECT {}", remote_addr);

            tokio::task::spawn(async move {
                let proxy = self;
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let mut upgraded = TokioIo::new(upgraded);
                        if let Err(err) = proxy.tunnel(&mut upgraded, remote_addr).await {
                            tracing::debug!("tunnel error: {}", err);
                        }
                    }
                    Err(err) => tracing::debug!("upgrade error: {}", err),
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

            tracing::trace!("resolving {}:{}", host, port);
            let stream = self.connector.connect_host(&host, port).await?;

            if let (Ok(local_addr), Ok(peer_addr)) = (stream.local_addr(), stream.peer_addr()) {
                if host.parse::<IpAddr>().is_ok() {
                    tracing::debug!("{} → {}", host, local_addr.ip());
                } else {
                    tracing::debug!("{} ({}) → {}", host, peer_addr.ip(), local_addr.ip());
                }
            } else if let Ok(local_addr) = stream.local_addr() {
                tracing::debug!("{} → {}", host, local_addr.ip());
            } else {
                tracing::debug!("{} → <unknown>", host);
            }

            let io = TokioIo::new(stream);
            let (mut sender, connection) = client_http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(io)
                .await?;

            tokio::task::spawn(async move {
                if let Err(err) = connection.without_shutdown().await {
                    tracing::debug!("upstream error: {}", err);
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
            tracing::trace!("DNS resolving {}", addr_str);
            if let Ok(addrs) = addr_str.to_socket_addrs() {
                for addr in addrs {
                    tracing::trace!("trying {}", addr);
                    if let Ok(mut server) = self.connector.connect_addr(addr).await {
                        if let Ok(local) = server.local_addr() {
                            tracing::debug!("{} → {}", addr_str, local.ip());
                        }
                        tokio::io::copy_bidirectional(upgraded, &mut server).await?;
                        return Ok(());
                    }
                }
            } else {
                tracing::debug!("DNS resolution failed: {}", addr_str);
            }

            Ok(())
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
        tracing::info!("SOCKS5 proxy listening on {}", listen_addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let connector_for_task = connector.clone();

            tokio::task::spawn({
                let conn_id = crate::logging::new_conn_id();
                let span = tracing::debug_span!("socks", conn_id = %conn_id);

                async move {
                    if let Err(err) = handle_connection(connector_for_task, stream).await {
                        tracing::debug!("SOCKS5 error: {}", err);
                    }
                }
                .instrument(span)
            });
        }
    }

    async fn handle_connection(
        connector: OutboundConnector,
        stream: TcpStream,
    ) -> Result<(), SocksProxyError> {
        let local_ip = stream.local_addr().ok().map(|addr| addr.ip());
        tracing::trace!("SOCKS5 handshake");
        let proto = Socks5ServerProtocol::accept_no_auth(stream).await?;
        let (proto, cmd, target_addr_unresolved) = proto.read_command().await?;

        let original_target = target_addr_unresolved.to_string();
        let (proto, cmd, target_addr) = (proto, cmd, target_addr_unresolved).resolve_dns().await?;

        match cmd {
            Socks5Command::TCPConnect => {
                tracing::debug!("CONNECT {}", original_target);
                handle_tcp_connect(connector, proto, original_target, target_addr).await
            }
            Socks5Command::UDPAssociate => {
                tracing::debug!("UDP ASSOCIATE {}", original_target);
                handle_udp_associate(connector, proto, original_target, target_addr, local_ip).await
            }
            _ => {
                tracing::debug!("unsupported command: {:?}", cmd);
                proto.reply_error(&ReplyError::CommandNotSupported).await?;
                Ok(())
            }
        }
    }

    async fn handle_tcp_connect<T>(
        connector: OutboundConnector,
        proto: Socks5ServerProtocol<T, states::CommandRead>,
        original_target: String,
        target_addr: TargetAddr,
    ) -> Result<(), SocksProxyError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let destination = match target_addr {
            TargetAddr::Ip(addr) => addr,
            TargetAddr::Domain(_, _) => {
                tracing::debug!("domain resolution not supported in SOCKS5");
                proto.reply_error(&ReplyError::GeneralFailure).await?;
                return Ok(());
            }
        };

        tracing::trace!("connecting to {}", destination);
        let outbound = match connector.connect_addr(destination).await {
            Ok(stream) => stream,
            Err(err) => {
                tracing::debug!("connection failed: {}", err);
                let reply = reply_error_for_io(&err);
                proto.reply_error(&reply).await?;
                return Err(err.into());
            }
        };

        let local_addr = match outbound.local_addr() {
            Ok(addr) => {
                if original_target.contains(&destination.ip().to_string()) {
                    tracing::debug!("{} → {}", destination.ip(), addr.ip());
                } else {
                    tracing::debug!("{} ({}) → {}", original_target, destination.ip(), addr.ip());
                }
                addr
            }
            Err(_) => {
                tracing::debug!("{} → <unknown>", original_target);
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            }
        };

        let mut inbound = proto.reply_success(local_addr).await?;
        transfer(&mut inbound, outbound).await;
        Ok(())
    }

    async fn handle_udp_associate<T>(
        connector: OutboundConnector,
        proto: Socks5ServerProtocol<T, states::CommandRead>,
        original_target: String,
        target_addr: TargetAddr,
        local_reply_ip: Option<IpAddr>,
    ) -> Result<(), SocksProxyError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let reply_ip = match local_reply_ip {
            Some(ip) => ip,
            None => {
                tracing::debug!("unable to determine local IP for UDP associate");
                proto.reply_error(&ReplyError::GeneralFailure).await?;
                return Ok(());
            }
        };

        let destination = match target_addr {
            TargetAddr::Ip(addr) => addr,
            TargetAddr::Domain(_, _) => {
                tracing::debug!("domain resolution not supported in SOCKS5 UDP");
                proto.reply_error(&ReplyError::GeneralFailure).await?;
                return Ok(());
            }
        };

        let outbound_ip = match connector.random_local_ip_for(destination.ip()) {
            Ok(ip) => ip,
            Err(err) => {
                tracing::debug!("UDP outbound bind selection failed: {}", err);
                let reply = reply_error_for_io(&err);
                proto.reply_error(&reply).await?;
                return Err(err.into());
            }
        };

        let resolved_target = TargetAddr::Ip(destination);

        tracing::debug!(
            "UDP associate {} → {} (relay {}, outbound {})",
            original_target,
            destination,
            reply_ip,
            outbound_ip
        );

        run_udp_proxy(
            proto,
            &resolved_target,
            Some(reply_ip),
            reply_ip,
            Some(outbound_ip),
        )
        .await?;
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
