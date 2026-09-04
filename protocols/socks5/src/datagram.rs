//! Датаграммный канал, выданный командой `UDP ASSOCIATE`.
//!
//! # Почему датаграммы идут мимо TLS
//!
//! У `socks5-tls` в TLS заворачивается управляющее соединение, а датаграммы —
//! нет: TLS живёт поверх потока, а здесь потока нет вовсе. Значит, под
//! `socks5-tls` каждый запрос DNS уходит открытым текстом ровно так же, как
//! под обычным `socks5`. Сказать об этом обязано окно — здесь это записано,
//! чтобы правка не сделала вид, будто прикрыто и это.
//!
//! # Почему здесь лежит управляющее соединение
//!
//! Прокси держит разрешение слать датаграммы ровно столько, сколько живёт то
//! соединение, которым это разрешение попросили (RFC 1928, §7). Закрыть его
//! после ответа — значит получить канал, который замолкает через секунду, и
//! искать причину в чём угодно, кроме собственного `drop`. Поэтому соединение
//! лежит в структуре и умирает вместе с ней.
//!
//! # Откуда приходят ответы
//!
//! Прокси отвечает со своего адреса, но порт может оказаться другим: адрес,
//! названный в ответе на `UDP ASSOCIATE`, — это куда слать, а не откуда
//! получать. Поэтому отправитель сверяется по адресу, а не по паре
//! «адрес и порт»: строгая сверка молча убивала бы весь UDP на половине
//! прокси, а полное её отсутствие означало бы, что подделать ответ DNS может
//! кто угодно из той же сети.

use std::net::SocketAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;
use tokio::net::UdpSocket;

use crate::frame::udp;

/// Канал датаграмм через прокси.
pub struct Socks5Datagram {
    socket: UdpSocket,
    /// Куда слать: адрес, названный прокси в ответе на `UDP ASSOCIATE`.
    relay: SocketAddr,
    /// Управляющее соединение. Не используется — но пока оно живо, живёт и
    /// разрешение слать датаграммы.
    ///
    /// Под замком не ради доступа: его не трогают вовсе. `ProxyStream` не
    /// `Sync` — поток принадлежит одной задаче, — а канал датаграмм общий, и
    /// замок здесь единственное, что позволяет одному лежать внутри другого.
    _control: Mutex<Box<dyn ProxyStream>>,
}

impl std::fmt::Debug for Socks5Datagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5Datagram")
            .field("relay", &self.relay)
            .finish()
    }
}

impl Socks5Datagram {
    /// Собирает канал вокруг уже открытого сокета и выданного адреса.
    pub fn new(socket: UdpSocket, relay: SocketAddr, control: Box<dyn ProxyStream>) -> Self {
        Self {
            socket,
            relay,
            _control: Mutex::new(control),
        }
    }
}

#[async_trait]
impl ProxyDatagram for Socks5Datagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let frame = udp::encode(target, &payload)?;
        self.socket.send_to(&frame, self.relay).await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        loop {
            // 65 535 — наибольшая датаграмма, которую вообще можно получить.
            // Обрезать её было бы порчей данных: приложение не узнает о потере.
            let mut buf = vec![0u8; 65_535];
            let (len, from) = self.socket.recv_from(&mut buf).await?;

            // Чужая датаграмма — это фон открытого порта, а не ошибка канала.
            if from.ip() != self.relay.ip() {
                tracing::debug!(%from, "датаграмма не от прокси — отброшена");
                continue;
            }

            match udp::decode(&buf[..len])? {
                Some((source, payload)) => return Ok((payload, source)),
                // Дроблёная или короче заголовка: взять из неё нечего, и это
                // для UDP то же самое, что потерянный пакет.
                None => continue,
            }
        }
    }
}
