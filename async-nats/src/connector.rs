// Copyright 2020-2022 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::auth::Auth;
use crate::connection::Connection;
use crate::connection::ReadOpError;
use crate::connection::State;
use crate::handle_events;
use crate::options::CallbackArg1;
use crate::tls;
use crate::AuthError;
use crate::ClientOp;
use crate::ConnectInfo;
use crate::ConnectOptions;
use crate::Event;
use crate::MaybeArc;
use crate::Protocol;
use crate::ServerAddr;
use crate::ServerError;
use crate::ServerInfo;
use crate::ServerOp;
use crate::SocketAddr;
use crate::ToServerAddrs;
use crate::LANG;
use crate::VERSION;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::engine::Engine;
use futures::FutureExt;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::cmp;
use std::error::Error as StdError;
use std::fmt;
use std::fmt::Display;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_rustls::rustls;

pub struct ConnectorOptions {
    pub(crate) tls_required: bool,
    pub(crate) certificates: Vec<PathBuf>,
    pub(crate) client_cert: Option<PathBuf>,
    pub(crate) client_key: Option<PathBuf>,
    pub(crate) tls_client_config: Option<rustls::ClientConfig>,
    pub(crate) tls_first: bool,
    pub(crate) auth: Auth,
    pub(crate) no_echo: bool,
    pub(crate) connection_timeout: Duration,
    pub(crate) name: Option<String>,
    pub(crate) ignore_discovered_servers: bool,
    pub(crate) retain_servers_order: bool,
    pub(crate) read_buffer_capacity: u16,
    pub(crate) reconnect_delay_callback: Box<dyn Fn(usize) -> Duration + Send + Sync + 'static>,
    pub(crate) auth_callback: Option<CallbackArg1<Vec<u8>, Result<Auth, AuthError>>>,
    pub(crate) max_reconnects: Option<usize>,
}

/// Maintains a list of servers and establishes connections.
pub(crate) struct Handler<const CLIENT_NODE: bool = true> {
    /// A map of servers and number of connect attempts.
    servers: Vec<(ServerAddr, usize)>,
    options: ConnectorOptions,
    attempts: usize,
    pub(crate) events_tx: tokio::sync::mpsc::Sender<Event>,
    pub(crate) state_tx: tokio::sync::watch::Sender<State>,
    pub(crate) max_payload: Arc<AtomicUsize>,
}

pub(crate) fn reconnect_delay_callback_default(attempts: usize) -> Duration {
    if attempts <= 1 {
        Duration::from_millis(0)
    } else {
        let exp: u32 = (attempts - 1).try_into().unwrap_or(std::u32::MAX);
        let max = Duration::from_secs(4);
        cmp::min(Duration::from_millis(2_u64.saturating_pow(exp)), max)
    }
}

pub struct Connector<const CLIENT_NODE: bool = true> {
    pub(crate) handler: Handler<CLIENT_NODE>,
    pub(crate) events_rx: tokio::sync::mpsc::Receiver<Event>,
    pub(crate) state_rx: tokio::sync::watch::Receiver<State>,
    pub(crate) subscription_capacity: usize,
    pub(crate) event_callback: Option<CallbackArg1<Event, ()>>,
    pub(crate) inbox_prefix: String,
    pub(crate) request_timeout: Option<Duration>,
    pub(crate) retry_on_initial_connect: bool,
    pub(crate) sender_capacity: usize,
    pub(crate) ping_interval: Duration,
}

pub fn create<A: ToServerAddrs>(addrs: A, options: ConnectOptions) -> Result<Connector, io::Error> {
    create_inner::<A, true>(addrs, options)
}

pub fn create_leaf_connector<A: ToServerAddrs>(
    addrs: A,
    options: ConnectOptions,
) -> Result<Connector<false>, io::Error> {
    create_inner::<A, false>(addrs, options)
}

fn create_inner<A: ToServerAddrs, const CLIENT_NODE: bool>(
    addrs: A,
    options: ConnectOptions,
) -> Result<Connector<CLIENT_NODE>, io::Error> {
    let ConnectOptions {
        name,
        no_echo,
        max_reconnects,
        connection_timeout,
        auth,
        tls_required,
        tls_first,
        certificates,
        client_cert,
        client_key,
        tls_client_config,
        ping_interval,
        subscription_capacity,
        sender_capacity,
        event_callback,
        inbox_prefix,
        request_timeout,
        retry_on_initial_connect,
        ignore_discovered_servers,
        retain_servers_order,
        read_buffer_capacity,
        reconnect_delay_callback,
        auth_callback,
    } = options;

    let options = ConnectorOptions {
        tls_required,
        certificates,
        client_cert,
        client_key,
        tls_client_config,
        tls_first,
        auth,
        no_echo,
        connection_timeout,
        name,
        ignore_discovered_servers,
        retain_servers_order,
        read_buffer_capacity,
        reconnect_delay_callback,
        auth_callback,
        max_reconnects,
    };

    let (events_tx, events_rx) = mpsc::channel(128);
    let (state_tx, state_rx) = tokio::sync::watch::channel(State::Pending);
    // We're setting it to the default server payload size.
    let max_payload = Arc::new(AtomicUsize::new(1024 * 1024));

    let handler = Handler::<CLIENT_NODE>::new(addrs, options, events_tx, state_tx, max_payload)?;
    Ok(Connector {
        handler,
        events_rx,
        state_rx,
        subscription_capacity,
        inbox_prefix,
        request_timeout,
        event_callback,
        retry_on_initial_connect,
        sender_capacity,
        ping_interval,
    })
}

impl<const CLIENT_NODE: bool> Connector<CLIENT_NODE> {
    pub async fn connect(&mut self) -> Result<(ServerInfo, Connection), MaybeArc<Error>> {
        let handle_events_fut =
            handle_events(&mut self.events_rx, self.event_callback.as_ref()).fuse();
        let connect_fut = self.handler.connect();

        tokio::pin!(handle_events_fut);
        tokio::pin!(connect_fut);

        loop {
            tokio::select! {
                result = connect_fut.as_mut() => {
                    return result;
                },

                () = handle_events_fut.as_mut() => {
                    tracing::warn!("events handler finished unexpectedly");
                },
            }
        }
    }

    pub async fn try_connect(&mut self) -> Result<(ServerInfo, Connection), Error> {
        let handle_events_fut =
            handle_events(&mut self.events_rx, self.event_callback.as_ref()).fuse();
        let try_connect_fut = self.handler.try_connect();

        tokio::pin!(handle_events_fut);
        tokio::pin!(try_connect_fut);

        loop {
            tokio::select! {
                result = try_connect_fut.as_mut() => {
                    return result;
                },

                () = handle_events_fut.as_mut() => {
                    tracing::warn!("events handler finished unexpectedly");
                },
            }
        }
    }
}

impl<const CLIENT_NODE: bool> Handler<CLIENT_NODE> {
    fn new<A: ToServerAddrs>(
        addrs: A,
        options: ConnectorOptions,
        events_tx: tokio::sync::mpsc::Sender<Event>,
        state_tx: tokio::sync::watch::Sender<State>,
        max_payload: Arc<AtomicUsize>,
    ) -> Result<Self, io::Error> {
        let servers = addrs.to_server_addrs()?.map(|addr| (addr, 0)).collect();

        Ok(Handler {
            attempts: 0,
            servers,
            options,
            events_tx,
            state_tx,
            max_payload,
        })
    }

    pub(crate) async fn connect(&mut self) -> Result<(ServerInfo, Connection), MaybeArc<Error>> {
        loop {
            match self.try_connect().await {
                Ok(inner) => return Ok(inner),
                Err(err @ Error::MaxReconnects(_)) => {
                    return Err(MaybeArc::Plain(err));
                }
                Err(err) => {
                    let err = Arc::new(err);
                    let _ = self
                        .events_tx
                        .send(Event::ClientError(Arc::clone(&err)))
                        .await;

                    if let Some(max_reconnects) = self.options.max_reconnects {
                        if self.attempts > max_reconnects {
                            return Err(MaybeArc::Arc(err));
                        }
                    }
                }
            }
        }
    }

    pub(crate) async fn try_connect(&mut self) -> Result<(ServerInfo, Connection), Error> {
        tracing::debug!("connecting");
        let mut error = None;

        let mut servers = self.servers.clone();
        if !self.options.retain_servers_order {
            servers.shuffle(&mut thread_rng());
            // sort_by is stable, meaning it will retain the order for equal elements.
            servers.sort_by(|a, b| a.1.cmp(&b.1));
        }

        for (server_addr, _) in servers {
            self.attempts += 1;
            if let Some(max_reconnects) = self.options.max_reconnects {
                if self.attempts > max_reconnects {
                    self.events_tx
                        .send(Event::ClientError(Arc::new(Error::MaxReconnects(None))))
                        .await
                        .ok();
                    return Err(Error::MaxReconnects(error));
                }
            }

            match self.try_connect_attempt(server_addr).await {
                Ok(ok) => return Ok(ok),
                Err(err) => {
                    error = Some(err);
                }
            }
        }

        Err(error.unwrap().into())
    }

    async fn try_connect_attempt(
        &mut self,
        server_addr: ServerAddr,
    ) -> Result<(ServerInfo, Connection), ConnectAttemptError> {
        use ConnectAttemptError as E;

        let duration = (self.options.reconnect_delay_callback)(self.attempts);

        sleep(duration).await;

        let socket_addrs = server_addr.socket_addrs().await.map_err(E::SocketAddrs)?;
        let mut error = None;
        for socket_addr in socket_addrs {
            match self
                .try_connect_to(&socket_addr, server_addr.tls_required(), server_addr.host())
                .await
            {
                Ok((server_info, mut connection)) => {
                    if !self.options.ignore_discovered_servers {
                        for url in &server_info.connect_urls {
                            let server_addr = url.parse::<ServerAddr>().map_err(E::InvalidPeer)?;
                            if !self.servers.iter().any(|(addr, _)| addr == &server_addr) {
                                self.servers.push((server_addr, 0));
                            }
                        }
                    }

                    let tls_required = self.options.tls_required || server_addr.tls_required();
                    let lang = if CLIENT_NODE {
                        LANG.to_string()
                    } else {
                        String::new()
                    };
                    let mut connect_info = ConnectInfo {
                        tls_required,
                        name: self.options.name.clone(),
                        pedantic: false,
                        verbose: false,
                        lang,
                        version: VERSION.to_string(),
                        protocol: Protocol::Dynamic,
                        user: self.options.auth.username.clone(),
                        pass: self.options.auth.password.clone(),
                        auth_token: self.options.auth.token.clone(),
                        user_jwt: None,
                        nkey: None,
                        signature: None,
                        echo: !self.options.no_echo,
                        headers: true,
                        no_responders: true,
                        m4ss_zstd: server_info.m4ss_zstd,
                    };

                    if let Some(nkey) = self.options.auth.nkey.as_ref() {
                        let key_pair =
                            nkeys::KeyPair::from_seed(nkey.as_str()).map_err(E::InvalidNKey)?;

                        let nonce = &server_info.nonce;
                        let signed = key_pair.sign(nonce.as_bytes()).map_err(E::SignWithNonce)?;
                        connect_info.nkey = Some(key_pair.public_key());
                        connect_info.signature = Some(URL_SAFE_NO_PAD.encode(signed));
                    }

                    if let Some((jwt, sign_fn)) = self
                        .options
                        .auth
                        .jwt
                        .as_ref()
                        .zip(self.options.auth.signature_callback.as_ref())
                    {
                        let sig = sign_fn
                            .call(server_info.nonce.clone())
                            .await
                            .map_err(E::JwtSignatureCallback)?;
                        connect_info.user_jwt = Some(jwt.clone());
                        connect_info.signature = Some(sig);
                    }

                    if let Some(callback) = self.options.auth_callback.as_ref() {
                        let auth = callback
                            .call(server_info.nonce.as_bytes().to_vec())
                            .await
                            .map_err(E::AuthCallback)?;
                        connect_info.user = auth.username;
                        connect_info.pass = auth.password;
                        connect_info.user_jwt = auth.jwt;
                        connect_info.signature = auth
                            .signature
                            .map(|signature| URL_SAFE_NO_PAD.encode(signature));
                        connect_info.auth_token = auth.token;
                        connect_info.nkey = auth.nkey;
                    }

                    #[cfg(feature = "zstd")]
                    let m4ss_zstd = connect_info.m4ss_zstd;

                    connection
                        .easy_write_and_flush([ClientOp::Connect(connect_info)].iter())
                        .await
                        .map_err(E::WriteStream)?;

                    #[cfg(feature = "zstd")]
                    if m4ss_zstd {
                        use std::pin::Pin;
                        use std::task::{Context, Poll, Waker};

                        use tokio::io::{AsyncRead, AsyncWrite, BufReader, ReadBuf};

                        #[derive(Debug)]
                        struct Maybe<T> {
                            item: Option<T>,
                            waker: Option<Waker>,
                        }

                        impl<T> Maybe<T> {
                            fn new(item: Option<T>) -> Self {
                                Self { item, waker: None }
                            }

                            fn take_item(&mut self) -> Option<T> {
                                self.item.take()
                            }

                            fn set_item(&mut self, item: T) {
                                self.item = Some(item);
                                if let Some(waker) = self.waker.take() {
                                    waker.wake();
                                }
                            }
                        }

                        impl<T: AsyncRead + Unpin> AsyncRead for Maybe<T> {
                            fn poll_read(
                                mut self: Pin<&mut Self>,
                                cx: &mut Context<'_>,
                                buf: &mut ReadBuf<'_>,
                            ) -> Poll<io::Result<()>> {
                                match &mut self.item {
                                    Some(item) => Pin::new(item).poll_read(cx, buf),
                                    None => {
                                        self.waker = Some(cx.waker().clone());
                                        Poll::Pending
                                    }
                                }
                            }
                        }

                        impl<T: AsyncWrite + Unpin> AsyncWrite for Maybe<T> {
                            fn poll_write(
                                mut self: Pin<&mut Self>,
                                cx: &mut Context<'_>,
                                buf: &[u8],
                            ) -> Poll<io::Result<usize>> {
                                match &mut self.item {
                                    Some(item) => Pin::new(item).poll_write(cx, buf),
                                    None => {
                                        self.waker = Some(cx.waker().clone());
                                        Poll::Pending
                                    }
                                }
                            }

                            fn poll_flush(
                                mut self: Pin<&mut Self>,
                                cx: &mut Context<'_>,
                            ) -> Poll<io::Result<()>> {
                                match &mut self.item {
                                    Some(item) => Pin::new(item).poll_flush(cx),
                                    None => {
                                        self.waker = Some(cx.waker().clone());
                                        Poll::Pending
                                    }
                                }
                            }

                            fn poll_shutdown(
                                self: Pin<&mut Self>,
                                _cx: &mut Context<'_>,
                            ) -> Poll<io::Result<()>> {
                                Poll::Ready(Ok(()))
                            }
                        }

                        let stream = connection.stream;

                        let decompressor = async_compression::tokio::bufread::ZstdDecoder::new(
                            BufReader::new(Maybe::new(Some(stream))),
                        );
                        let compressor = async_compression::tokio::write::ZstdEncoder::with_quality(
                            Maybe::new(None),
                            async_compression::Level::Precise(15),
                        );

                        struct CompressedStream<S> {
                            decompressor:
                                async_compression::tokio::bufread::ZstdDecoder<BufReader<Maybe<S>>>,
                            compressor: async_compression::tokio::write::ZstdEncoder<Maybe<S>>,
                        }

                        impl<S> AsyncRead for CompressedStream<S>
                        where
                            S: AsyncRead + AsyncWrite + Unpin,
                        {
                            fn poll_read(
                                mut self: Pin<&mut Self>,
                                cx: &mut Context<'_>,
                                buf: &mut ReadBuf<'_>,
                            ) -> Poll<io::Result<()>> {
                                if let Some(stream) = self.compressor.get_mut().take_item() {
                                    self.decompressor.get_mut().get_mut().set_item(stream);
                                }

                                Pin::new(&mut self.decompressor).poll_read(cx, buf)
                            }
                        }

                        impl<S> AsyncWrite for CompressedStream<S>
                        where
                            S: AsyncRead + AsyncWrite + Unpin,
                        {
                            fn poll_write(
                                mut self: Pin<&mut Self>,
                                cx: &mut Context<'_>,
                                buf: &[u8],
                            ) -> Poll<io::Result<usize>> {
                                if let Some(stream) =
                                    self.decompressor.get_mut().get_mut().take_item()
                                {
                                    self.compressor.get_mut().set_item(stream);
                                }

                                Pin::new(&mut self.compressor).poll_write(cx, buf)
                            }

                            fn poll_flush(
                                mut self: Pin<&mut Self>,
                                cx: &mut Context<'_>,
                            ) -> Poll<io::Result<()>> {
                                if let Some(stream) =
                                    self.decompressor.get_mut().get_mut().take_item()
                                {
                                    self.compressor.get_mut().set_item(stream);
                                }

                                Pin::new(&mut self.compressor).poll_flush(cx)
                            }

                            fn poll_shutdown(
                                self: Pin<&mut Self>,
                                _cx: &mut Context<'_>,
                            ) -> Poll<io::Result<()>> {
                                Poll::Ready(Ok(()))
                            }
                        }

                        connection.stream = Box::new(CompressedStream {
                            decompressor,
                            compressor,
                        });
                    }

                    connection
                        .easy_write_and_flush([ClientOp::Ping].iter())
                        .await
                        .map_err(E::WriteStream)?;

                    match connection.read_op().await.map_err(E::ReadOp)? {
                        Some(ServerOp::Error(err)) => {
                            return Err(E::ServerError(err));
                        }
                        Some(_) => {
                            tracing::debug!("connected to {}", server_info.port);
                            self.attempts = 0;
                            self.events_tx.send(Event::Connected).await.ok();
                            self.state_tx.send(State::Connected).ok();
                            self.max_payload.store(
                                server_info.max_payload,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            return Ok((server_info, connection));
                        }
                        None => {
                            return Err(E::BrokenPipe);
                        }
                    }
                }

                Err(source) => {
                    error = Some(E::ConnectTo {
                        address: socket_addr,
                        tls_required: server_addr.tls_required(),
                        host: server_addr.host().to_owned(),
                        source,
                    });
                }
            };
        }

        Err(error.unwrap())
    }

    pub(crate) async fn try_connect_to(
        &self,
        socket_addr: &SocketAddr,
        tls_required: bool,
        tls_host: &str,
    ) -> Result<(ServerInfo, Connection), ConnectToError> {
        use ConnectToError as E;

        let tcp_stream = tokio::time::timeout(
            self.options.connection_timeout,
            TcpStream::connect(socket_addr),
        )
        .await
        .map_err(|_| E::Timeout)?
        .map_err(E::Connect)?;

        tcp_stream.set_nodelay(true).map_err(E::NoDelay)?;

        let mut connection = Connection::new(
            Box::new(tcp_stream),
            self.options.read_buffer_capacity.into(),
        );

        let tls_connection = |connection: Connection| async {
            let tls_config = Arc::new(tls::config_tls(&self.options).await.map_err(E::ConfigTls)?);
            let tls_connector = tokio_rustls::TlsConnector::from(tls_config);

            let domain = webpki::types::ServerName::try_from(tls_host).map_err(E::ServerName)?;

            let tls_stream = tls_connector
                .connect(domain.to_owned(), connection.stream)
                .await
                .map_err(E::TlsConnect)?;

            Ok(Connection::new(Box::new(tls_stream), 0))
        };

        // If `tls_first` was set, establish TLS connection before getting INFO.
        // There is no point in  checking if tls is required, because
        // the connection has to be be upgraded to TLS anyway as it's different flow.
        if self.options.tls_first {
            connection = tls_connection(connection).await?;
        }

        let op = connection.read_op().await.map_err(E::ReadOp)?;
        let info = match op {
            Some(ServerOp::Info(info)) => info,
            Some(op) => return Err(E::ExpectedInfo(op.to_str())),
            None => return Err(E::BrokenPipe),
        };

        // If `tls_first` was not set, establish TLS connection if it is required.
        if !self.options.tls_first
            && (self.options.tls_required || info.tls_required || tls_required)
        {
            connection = tls_connection(connection).await?;
        };

        Ok((*info, connection))
    }
}

/// Returned when initial connection fails.
#[derive(Debug)]
pub enum Error {
    MaxReconnects(Option<ConnectAttemptError>),
    Attempt(ConnectAttemptError),
}

impl From<ConnectAttemptError> for Error {
    fn from(value: ConnectAttemptError) -> Self {
        Self::Attempt(value)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MaxReconnects(_) => f.write_str("max number of reconnections reached"),
            Error::Attempt(_) => f.write_str("connection attempt failed"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::MaxReconnects(source) => source.as_ref().map(|err| err as &dyn StdError),
            Error::Attempt(source) => Some(source),
        }
    }
}

/// Returned when initial connection fails.
#[derive(Debug)]
pub enum ConnectAttemptError {
    SocketAddrs(io::Error),
    InvalidPeer(io::Error),
    InvalidNKey(nkeys::error::Error),
    SignWithNonce(nkeys::error::Error),
    JwtSignatureCallback(AuthError),
    AuthCallback(AuthError),
    WriteStream(io::Error),
    ReadOp(ReadOpError),
    ServerError(ServerError),
    BrokenPipe,
    ConnectTo {
        address: SocketAddr,
        tls_required: bool,
        host: String,
        source: ConnectToError,
    },
}

impl Display for ConnectAttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectAttemptError::SocketAddrs(_) => f.write_str("invalid socket address"),
            ConnectAttemptError::InvalidPeer(_) => f.write_str("invalid peer"),
            ConnectAttemptError::InvalidNKey(_) => f.write_str("invalid nkey"),
            ConnectAttemptError::SignWithNonce(_) => f.write_str("unable to sign with none"),
            ConnectAttemptError::JwtSignatureCallback(_) => f.write_str("cannot sign jwt"),
            ConnectAttemptError::AuthCallback(_) => f.write_str("cannot authenticate"),
            ConnectAttemptError::WriteStream(_) => f.write_str("cannot write to stream"),
            ConnectAttemptError::ReadOp(_) => f.write_str("cannot read op from strem"),
            ConnectAttemptError::ServerError(_) => f.write_str("error received from server"),
            ConnectAttemptError::BrokenPipe => f.write_str("broken pipe"),
            &ConnectAttemptError::ConnectTo {
                address,
                tls_required,
                ref host,
                source: _,
            } => {
                let with_without_tls = if tls_required { "with" } else { "without" };
                write!(
                    f,
                    r#"unable to connect to address {address} {with_without_tls} TLS using \
                    "{host}" as host"#,
                )
            }
        }
    }
}

impl StdError for ConnectAttemptError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ConnectAttemptError::SocketAddrs(source)
            | ConnectAttemptError::InvalidPeer(source)
            | ConnectAttemptError::WriteStream(source) => Some(source),
            ConnectAttemptError::InvalidNKey(source)
            | ConnectAttemptError::SignWithNonce(source) => Some(source),
            ConnectAttemptError::JwtSignatureCallback(source)
            | ConnectAttemptError::AuthCallback(source) => Some(source),
            ConnectAttemptError::ReadOp(source) => Some(source),
            ConnectAttemptError::ServerError(source) => Some(source),
            ConnectAttemptError::BrokenPipe => None,
            ConnectAttemptError::ConnectTo { source, .. } => Some(source),
        }
    }
}

#[derive(Debug)]
pub enum ConnectToError {
    Timeout,
    Connect(io::Error),
    NoDelay(io::Error),
    ConfigTls(io::Error),
    ServerName(webpki::types::InvalidDnsNameError),
    TlsConnect(io::Error),
    ReadOp(ReadOpError),
    ExpectedInfo(&'static str),
    BrokenPipe,
}

impl Display for ConnectToError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectToError::Timeout => f.write_str("connection timed out"),
            ConnectToError::Connect(_) => f.write_str("unable to connect to remote host"),
            ConnectToError::NoDelay(_) => f.write_str("unable to set TCP stream to NO_DELAY"),
            ConnectToError::ConfigTls(_) => f.write_str("unable to config TLS"),
            ConnectToError::ServerName(_) => f.write_str("invalid server name"),
            ConnectToError::TlsConnect(_) => f.write_str("unable to perform TLS connection"),
            ConnectToError::ReadOp(_) => f.write_str("unable to read op"),
            ConnectToError::ExpectedInfo(op) => write!(f, "expected INFO op, obtained {op:?}"),
            ConnectToError::BrokenPipe => f.write_str("broken pipe"),
        }
    }
}

impl StdError for ConnectToError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ConnectToError::Timeout
            | ConnectToError::ExpectedInfo(_)
            | ConnectToError::BrokenPipe => None,
            ConnectToError::Connect(source)
            | ConnectToError::NoDelay(source)
            | ConnectToError::ConfigTls(source)
            | ConnectToError::TlsConnect(source) => Some(source),
            ConnectToError::ServerName(source) => Some(source),
            ConnectToError::ReadOp(source) => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_delay_callback_duration() {
        let duration = reconnect_delay_callback_default(0);
        assert_eq!(duration.as_millis(), 0);

        let duration = reconnect_delay_callback_default(1);
        assert_eq!(duration.as_millis(), 0);

        let duration = reconnect_delay_callback_default(4);
        assert_eq!(duration.as_millis(), 8);

        let duration = reconnect_delay_callback_default(12);
        assert_eq!(duration.as_millis(), 2048);

        let duration = reconnect_delay_callback_default(13);
        assert_eq!(duration.as_millis(), 4000);

        // The max (4s) was reached and we shouldn't exceed it, regardless of the no of attempts
        let duration = reconnect_delay_callback_default(50);
        assert_eq!(duration.as_millis(), 4000);
    }
}
