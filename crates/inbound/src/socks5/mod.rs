//! Локальный SOCKS5-прокси. Работает без прав администратора и без драйвера.
//!
//! Самый дешёвый способ проверить, что протокол реализован верно: приложение
//! настраивается на `127.0.0.1:1080`, и трафик идёт через тоннель, не трогая
//! ни маршруты, ни адаптеры, ни брандмауэр.
//!
//! У режима есть и своё преимущество перед TUN: приложение отдаёт **имя**
//! хоста, а не адрес. Значит, утечки DNS нет по построению — разрешать имя
//! будет сервер на той стороне.
//!
//! Ограничение ровно одно, и оно принципиальное: работает только для
//! приложений, которые умеют и настроены ходить через прокси. Всё остальное —
//! задача TUN.

pub mod address;
pub mod auth;
pub mod handshake;
pub mod request;
pub mod udp;

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_core::network::Network;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use self::auth::Credentials;
use self::handshake::Chosen;
use self::request::Command;
use crate::error::{InboundError, InboundResult};
use crate::inbound::{Inbound, InboundHandler, InboundRequest};

/// Наибольший размер датаграммы, которую мы готовы принять от приложения.
const UDP_BUFFER: usize = 65_535;

/// Локальный SOCKS5-прокси.
pub struct Socks5Inbound {
    listener: TcpListener,
    handler: Arc<dyn InboundHandler>,
    credentials: Option<Credentials>,
}

impl Socks5Inbound {
    /// Занимает адрес и готовится обслуживать соединения.
    ///
    /// Адрес занимается сразу, а не в `serve`: ошибка «порт занят» должна
    /// прийти тому, кто запускал клиент, а не утонуть в фоновой задаче.
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
        loop {
            let accepted = tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                accepted = self.listener.accept() => accepted,
            };

            let (stream, source) = match accepted {
                Ok(pair) => pair,
                Err(err) => {
                    // Исчерпание дескрипторов лечится только тем, что часть
                    // соединений закроется. Выходить из цикла нельзя — прокси
                    // перестал бы работать насовсем.
                    tracing::warn!(%err, "не удалось принять соединение");
                    continue;
                }
            };

            let handler = Arc::clone(&self.handler);
            let credentials = self.credentials.clone();
            let cancel = cancel.clone();

            tokio::spawn(async move {
                if let Err(err) =
                    serve_connection(stream, source, handler, credentials, cancel).await
                {
                    // Обычный фон: клиент передумал, вкладка закрылась.
                    // Уровень отладочный намеренно — иначе журнал состоит из
                    // этих строк.
                    tracing::debug!(%source, %err, "соединение SOCKS5 завершилось с ошибкой");
                }
            });
        }

        tracing::info!("SOCKS5 остановлен");
    }
}

/// Обслуживает одно соединение от начала до конца.
async fn serve_connection(
    mut stream: TcpStream,
    source: SocketAddr,
    handler: Arc<dyn InboundHandler>,
    credentials: Option<Credentials>,
    cancel: CancellationToken,
) -> InboundResult<()> {
    // Задержка Нейгла на прокси вредна: она копит мелкие записи, а через
    // прокси идут именно они — заголовки запросов и подтверждения.
    let _ = stream.set_nodelay(true);

    match handshake::negotiate(&mut stream, credentials.is_some()).await? {
        Chosen::NoAuth => {}
        Chosen::UserPass => {
            let expected = credentials.as_ref().ok_or(InboundError::AuthFailed)?;
            auth::verify(&mut stream, expected).await?;
        }
    }

    let command = match request::read(&mut stream).await {
        Ok(command) => command,
        Err(err) => {
            // Отказ полагается отправить: без него клиент ждёт до тайм-аута.
            let _ = request::reply_failure(&mut stream, err.socks5_reply()).await;
            return Err(err);
        }
    };

    match command {
        Command::Connect(target) => connect(stream, source, target, handler).await,
        Command::UdpAssociate(_) => associate(stream, source, handler, cancel).await,
    }
}

/// Обслуживает CONNECT.
async fn connect(
    mut stream: TcpStream,
    source: SocketAddr,
    target: SocketAddress,
    handler: Arc<dyn InboundHandler>,
) -> InboundResult<()> {
    let request = InboundRequest {
        source,
        target: target.clone(),
        network: Network::Tcp,
    };

    let outbound = match handler.open_tcp(&request).await {
        Ok(outbound) => outbound,
        Err(err) => {
            tracing::debug!(%target, %err, "не удалось открыть соединение");
            let _ = request::reply_failure(&mut stream, protocol_error_to_reply(&err)).await;
            return Ok(());
        }
    };

    // Ответ уходит только теперь: код в нём — результат настоящей попытки.
    let bound = stream.local_addr()?;
    request::reply_success(&mut stream, bound).await?;

    let (mut client_read, mut client_write) = stream.into_split();
    let (mut remote_read, mut remote_write) = tokio::io::split(outbound);

    // Обе половины качаются одновременно и до конца: полузакрытое соединение
    // — законное состояние, и обрывать вторую половину, когда кончилась
    // первая, значит терять хвост ответа.
    let (up, down) = tokio::join!(
        async {
            let result = tokio::io::copy(&mut client_read, &mut remote_write).await;
            let _ = remote_write.shutdown().await;
            result
        },
        async {
            let result = tokio::io::copy(&mut remote_read, &mut client_write).await;
            let _ = client_write.shutdown().await;
            result
        }
    );

    tracing::debug!(
        %target,
        uploaded = up.unwrap_or(0),
        downloaded = down.unwrap_or(0),
        "соединение закрыто"
    );
    Ok(())
}

/// Обслуживает UDP ASSOCIATE.
async fn associate(
    mut stream: TcpStream,
    source: SocketAddr,
    handler: Arc<dyn InboundHandler>,
    cancel: CancellationToken,
) -> InboundResult<()> {
    // Сокет на том же адресе, что и слушающий: клиент шлёт датаграммы туда,
    // куда мы скажем в ответе, а сказать надо адрес, до которого он достучится.
    let bind_ip = stream.local_addr()?.ip();
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    let local = socket.local_addr()?;

    let request = InboundRequest {
        source,
        // Направление ещё не известно: адрес назначения появится с первой
        // датаграммой. Маршрутизатор увидит его при первой же отправке.
        target: SocketAddress::ip(bind_ip, 0),
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

    let socket = Arc::new(socket);
    let outbound = Arc::new(outbound);

    // Адрес клиента узнаётся из первой пришедшей датаграммы: в запросе он
    // часто нулевой, потому что приложение само ещё не знает своего порта.
    let client: Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    let uplink = {
        let socket = Arc::clone(&socket);
        let outbound = Arc::clone(&outbound);
        let client = Arc::clone(&client);
        async move {
            let mut buf = vec![0u8; UDP_BUFFER];
            loop {
                let Ok((len, from)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                let Some(packet) = udp::decode(&buf[..len]) else {
                    continue;
                };

                *client.lock().await = Some(from);

                let payload = Bytes::copy_from_slice(packet.payload);
                if let Err(err) = outbound.send_to(payload, &packet.target).await {
                    tracing::debug!(%err, "датаграмма не отправлена");
                }
            }
        }
    };

    let downlink = {
        let socket = Arc::clone(&socket);
        let outbound = Arc::clone(&outbound);
        let client = Arc::clone(&client);
        async move {
            loop {
                let Ok((payload, from)) = outbound.recv_from().await else {
                    break;
                };
                let Some(to) = *client.lock().await else {
                    continue;
                };
                let datagram = udp::encode(&from, &payload);
                if let Err(err) = socket.send_to(&datagram, to).await {
                    tracing::debug!(%err, "ответ не доставлен приложению");
                    break;
                }
            }
        }
    };

    // Сессия живёт ровно столько, сколько открыто управляющее соединение.
    // У UDP закрытия нет, и без этой привязки сокет висел бы до конца работы
    // клиента.
    let control_closed = async {
        let mut buf = [0u8; 1];
        loop {
            match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                // Ноль байт — клиент закрыл управляющее соединение.
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
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

/// Переводит ошибку протокола в код ответа SOCKS5.
fn protocol_error_to_reply(err: &penguin_proto::error::ProtocolError) -> u8 {
    use penguin_proto::error::ProtocolError;
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
    use penguin_proto::error::ProtocolError;

    use super::*;

    #[test]
    fn protocol_errors_map_to_meaningful_codes() {
        // Браузер по коду показывает разные сообщения; общий 0x01 на всё
        // превратил бы разбор неполадок в гадание.
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
