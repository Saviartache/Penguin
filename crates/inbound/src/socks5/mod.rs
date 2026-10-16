//! Локальный SOCKS5-прокси: без прав и драйвера, приложение отдаёт имя хоста.
//! Работает только для приложений, настроенных на прокси; остальное — задача TUN.

pub mod address;
pub mod auth;
pub mod handshake;
pub mod request;
pub mod udp;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use penguin_core::address::SocketAddress;
use penguin_core::network::Network;
use penguin_proto::error::ProtocolError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use self::auth::Credentials;
use self::handshake::Chosen;
use self::request::Command;
use crate::error::{InboundError, InboundResult};
use crate::inbound::{Inbound, InboundHandler, InboundRequest};
use crate::relay::relay;

/// Наибольший размер датаграммы от приложения.
const UDP_BUFFER: usize = 65_535;

/// Локальный SOCKS5-прокси.
pub struct Socks5Inbound {
    listener: TcpListener,
    handler: Arc<dyn InboundHandler>,
    credentials: Option<Credentials>,
}

impl Socks5Inbound {
    /// Занимает адрес сразу, чтобы «порт занят» дошло до запускающего.
    pub async fn bind(
        listen: SocketAddr,
        handler: Arc<dyn InboundHandler>,
        credentials: Option<Credentials>,
    ) -> InboundResult<Self> {
        let listener = TcpListener::bind(listen).await?;
        tracing::info!(addr = %listener.local_addr()?, "SOCKS5 слушает");
        Ok(Self {
            listener,
            handler,
            credentials,
        })
    }
}

#[async_trait]
impl Inbound for Socks5Inbound {
    fn name(&self) -> &'static str {
        "socks5"
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.listener.local_addr().ok()
    }

    async fn serve(self: Box<Self>, cancel: CancellationToken) {
        let credentials = self.credentials.map(Arc::new);
        loop {
            let accepted = tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                accepted = self.listener.accept() => accepted,
            };

            let (stream, source) = match accepted {
                Ok(pair) => pair,
                Err(err) => {
                    // Выходить нельзя: прокси перестал бы работать насовсем.
                    tracing::warn!(%err, "не удалось принять соединение");
                    continue;
                }
            };

            let handler = Arc::clone(&self.handler);
            let credentials = credentials.clone();
            let cancel = cancel.clone();

            tokio::spawn(async move {
                if let Err(err) =
                    serve_connection(stream, source, handler, credentials, cancel).await
                {
                    tracing::debug!(%source, %err, "соединение SOCKS5 завершилось с ошибкой");
                }
            });
        }

        tracing::info!("SOCKS5 остановлен");
    }
}

async fn serve_connection(
    mut stream: TcpStream,
    source: SocketAddr,
    handler: Arc<dyn InboundHandler>,
    credentials: Option<Arc<Credentials>>,
    cancel: CancellationToken,
) -> InboundResult<()> {
    // Nagle копит мелкие записи, а через прокси идут именно они.
    let _ = stream.set_nodelay(true);

    match handshake::negotiate(&mut stream, credentials.is_some()).await? {
        Chosen::NoAuth => {}
        Chosen::UserPass => {
            let expected = credentials.as_deref().ok_or(InboundError::AuthFailed)?;
            auth::verify(&mut stream, expected).await?;
        }
    }

    let command = match request::read(&mut stream).await {
        Ok(command) => command,
        Err(err) => {
            let _ = request::reply_failure(&mut stream, err.socks5_reply()).await;
            return Err(err);
        }
    };

    match command {
        Command::Connect(target) => connect(stream, source, target, handler).await,
        Command::UdpAssociate(_) => associate(stream, source, handler, cancel).await,
    }
}

async fn connect(
    mut stream: TcpStream,
    source: SocketAddr,
    target: SocketAddress,
    handler: Arc<dyn InboundHandler>,
) -> InboundResult<()> {
    let request = InboundRequest {
        source,
        target,
        sniffed: None,
        network: Network::Tcp,
    };

    let mut outbound = match handler.open_tcp(&request).await {
        Ok(outbound) => outbound,
        Err(err) => {
            tracing::debug!(target = %request.target, %err, "не удалось открыть соединение");
            let _ = request::reply_failure(&mut stream, protocol_error_to_reply(&err)).await;
            return Ok(());
        }
    };

    let bound = stream.local_addr()?;
    request::reply_success(&mut stream, bound).await?;

    relay(&mut stream, &mut outbound, &request.target).await;
    Ok(())
}

async fn associate(
    mut stream: TcpStream,
    source: SocketAddr,
    handler: Arc<dyn InboundHandler>,
    cancel: CancellationToken,
) -> InboundResult<()> {
    // Адрес сокета сообщается клиенту, поэтому он на том же интерфейсе, что и TCP.
    let bind_ip = stream.local_addr()?.ip();
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    let local = socket.local_addr()?;

    // Назначение неизвестно до первой датаграммы.
    let request = InboundRequest {
        source,
        target: SocketAddress::ip(bind_ip, 0),
        sniffed: None,
        network: Network::Udp,
    };

    let outbound = match handler.open_udp(&request).await {
        Ok(outbound) => outbound,
        Err(err) => {
            tracing::debug!(%err, "UDP недоступен");
            let _ = request::reply_failure(&mut stream, protocol_error_to_reply(&err)).await;
            return Ok(());
        }
    };

    request::reply_success(&mut stream, local).await?;

    let client = Mutex::new(None::<SocketAddr>);

    let uplink = async {
        let mut buf = vec![0u8; UDP_BUFFER];
        loop {
            let Ok((len, from)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let Some(packet) = udp::decode(&buf[..len]) else {
                continue;
            };
            set_client(&client, from);

            if let Err(err) = outbound
                .send_to(Bytes::copy_from_slice(packet.payload), &packet.target)
                .await
            {
                tracing::debug!(%err, "датаграмма не отправлена");
            }
        }
    };

    let downlink = async {
        let mut out = BytesMut::new();
        loop {
            let Ok((payload, from)) = outbound.recv_from().await else {
                break;
            };
            let Some(to) = get_client(&client) else {
                continue;
            };
            udp::encode_into(&mut out, &from, &payload);
            if let Err(err) = socket.send_to(&out, to).await {
                tracing::debug!(%err, "ответ не доставлен приложению");
                break;
            }
        }
    };

    // Сессия живёт, пока открыто управляющее TCP-соединение: у UDP закрытия нет.
    let control_closed = async {
        let mut buf = [0u8; 1];
        while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
    };

    tokio::select! {
        () = uplink => {}
        () = downlink => {}
        () = control_closed => {}
        () = cancel.cancelled() => {}
    }

    let _ = outbound.close().await;
    tracing::debug!(%source, "сессия UDP завершена");
    Ok(())
}

fn set_client(slot: &Mutex<Option<SocketAddr>>, addr: SocketAddr) {
    *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(addr);
}

fn get_client(slot: &Mutex<Option<SocketAddr>>) -> Option<SocketAddr> {
    *slot.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Переводит ошибку протокола в код ответа SOCKS5.
fn protocol_error_to_reply(err: &ProtocolError) -> u8 {
    match err {
        ProtocolError::Unreachable(_) => 0x04,
        ProtocolError::Unsupported(_) => 0x07,
        ProtocolError::Io(err) => InboundError::Io(std::io::Error::from(err.kind())).socks5_reply(),
        _ => 0x01,
    }
}

/// Читает и пишет — общий набор требований к соединению с приложением.
pub trait ClientStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> ClientStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_errors_map_to_meaningful_codes() {
        assert_eq!(
            protocol_error_to_reply(&ProtocolError::Unreachable("x".into())),
            0x04
        );
        assert_eq!(
            protocol_error_to_reply(&ProtocolError::Unsupported("UDP")),
            0x07
        );
        assert_eq!(protocol_error_to_reply(&ProtocolError::AuthRejected), 0x01);
    }
}
