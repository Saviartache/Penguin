//! Направление через прокси SOCKS5.
//!
//! Состояния между вызовами не держит: мультиплексирования в SOCKS5 нет, и
//! каждое подключение — это своё TCP-соединение до прокси со своим
//! приветствием. Хранить тут нечего, кроме настроек, — и это же причина, по
//! которой [`Capabilities::multiplex`] у него `false`: маршрутизатор не должен
//! рассчитывать на дешёвое открытие потока.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::address::{Address, SocketAddress};
use penguin_core::id::OutboundId;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::connect;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use penguin_transport::deadline;
use penguin_transport::tls::{ALPN_HTTP11, TlsClient};

use crate::config::Socks5Config;
use crate::datagram::Socks5Datagram;
use crate::error::{Socks5Error, Socks5Result};
use crate::handshake::{self, CMD_CONNECT, CMD_UDP_ASSOCIATE};

/// Исходящее направление через прокси SOCKS5.
pub struct Socks5Outbound {
    id: OutboundId,
    config: Socks5Config,
    /// Хост прокси, разобранный один раз при сборке.
    host: Address,
    /// Порт прокси.
    port: u16,
    /// Собранный слой TLS. `None` — протокол `socks5`, разговор в открытую.
    ///
    /// Собирается один раз: разбор сертификатов на каждое открытие вкладки
    /// стоил бы дороже самого рукопожатия.
    tls: Option<TlsClient>,
    dialer: Arc<dyn Dialer>,
}

impl std::fmt::Debug for Socks5Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5Outbound")
            .field("id", &self.id)
            .field("config", &self.config)
            .field("tls", &self.tls.is_some())
            .finish()
    }
}

impl Socks5Outbound {
    /// Собирает направление, разобрав адрес прокси.
    ///
    /// Соединения при этом не открывается: адрес разбирается один раз, а
    /// подключается направление на каждый поток заново.
    pub fn new(
        id: OutboundId,
        config: Socks5Config,
        secure: bool,
        dialer: Arc<dyn Dialer>,
    ) -> Socks5Result<Self> {
        config.validate(secure)?;
        let (host, port) = config.endpoint()?;

        let tls = if secure {
            // ALPN — `http/1.1`: своего у SOCKS5 нет, а объявить нечего значит
            // отличаться от браузера первым же пакетом рукопожатия. Прокси,
            // которому ALPN безразличен, его просто не читает.
            Some(TlsClient::new(&config.tls, &host, &[ALPN_HTTP11])?)
        } else {
            None
        };

        Ok(Self {
            id,
            config,
            host,
            port,
            tls,
            dialer,
        })
    }

    /// Открывает соединение до прокси и проходит проверку подлинности.
    ///
    /// Возвращает готовый поток и адрес, к которому он подключён. Адрес нужен
    /// отдельно: под TLS до сокета уже не добраться, а `UDP ASSOCIATE` без
    /// него не разберёт, куда слать датаграммы.
    ///
    /// Срок здесь обязателен: прокси, принявший соединение и замолчавший,
    /// иначе держал бы поток приложения вечно — а выглядит это как страница,
    /// которая грузится и не загружается.
    async fn open(&self) -> Result<(Box<dyn ProxyStream>, SocketAddr), ProtocolError> {
        let plain = connect::dial(&*self.dialer, &self.host, self.port).await?;
        let proxy = plain.peer_addr()?;

        let mut io: Box<dyn ProxyStream> = match &self.tls {
            Some(tls) => Box::new(tls.connect(plain).await?),
            None => Box::new(plain),
        };

        deadline::handshake::<_, Socks5Error>("приветствие SOCKS5", async {
            handshake::negotiate(&mut io, self.config.credentials()).await
        })
        .await?;
        Ok((io, proxy))
    }

    /// Проверяет, что прокси на месте и пускает.
    ///
    /// Зовётся при подъёме направления. Без неё «Подключено» загоралось бы на
    /// профиле с неверным паролем: у SOCKS5 нет постоянного соединения, и
    /// узнать о нём было бы негде до первого открытого приложением потока —
    /// то есть в момент, когда виноватой будет выглядеть страница в браузере.
    pub async fn verify(&self) -> Result<(), ProtocolError> {
        let _connection = self.open().await?;
        Ok(())
    }

    /// Имя протокола: с TLS или без.
    fn name(&self) -> &'static str {
        if self.tls.is_some() {
            crate::PROTOCOL_TLS
        } else {
            crate::PROTOCOL
        }
    }
}

#[async_trait]
impl Outbound for Socks5Outbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        self.name()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // Ровно то, что стоит в настройках: соврать здесь означает, что
            // DNS-запросы уйдут в направление, которое их молча потеряет.
            udp: self.config.udp,
            multiplex: false,
            port_hopping: false,
            // Имя уезжает прокси доменом и разрешается на той стороне.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let (mut io, _proxy) = self.open().await?;
        deadline::handshake::<_, Socks5Error>("команда SOCKS5", async {
            handshake::command(&mut io, CMD_CONNECT, target).await
        })
        .await?;
        Ok(io)
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        if !self.config.udp {
            return Err(Socks5Error::UdpDisabled.into());
        }

        let (mut control, proxy) = self.open().await?;

        // Адрес, с которого мы будем слать, прокси знать не обязан: локальный
        // порт станет известен только после привязки, а требовать его заранее
        // означало бы привязать сокет до того, как выяснилось, что канал
        // вообще дадут. Нули здесь — обычная практика.
        let asked = SocketAddress::ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let bound = deadline::handshake::<_, Socks5Error>("команда SOCKS5", async {
            handshake::command(&mut control, CMD_UDP_ASSOCIATE, &asked).await
        })
        .await?;
        let relay = relay_address(&bound, proxy);

        let local = SocketAddr::new(
            if relay.is_ipv6() {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            },
            0,
        );
        let socket = self.dialer.bind_udp(local).await?;

        tracing::debug!(%relay, "канал датаграмм открыт");
        Ok(Box::new(Socks5Datagram::new(socket, relay, control)))
    }
}

/// Куда слать датаграммы по ответу прокси.
///
/// Свободная функция с тестом, потому что здесь два места, где реализации
/// расходятся с текстом RFC:
///
/// - прокси часто отвечает `0.0.0.0`, имея в виду «туда же, куда и TCP»;
/// - имя вместо адреса встречается у прокси за NAT, и разрешать его здесь
///   нельзя — оно указывает на ту же машину, к которой мы уже подключены.
///
/// В обоих случаях берётся адрес, к которому подключено управляющее
/// соединение: он заведомо достижим, а обещанный — нет.
fn relay_address(bound: &SocketAddress, proxy: SocketAddr) -> SocketAddr {
    let port = if bound.port == 0 {
        proxy.port()
    } else {
        bound.port
    };

    match bound.host {
        Address::Ip(ip) if !ip.is_unspecified() => SocketAddr::new(ip, port),
        _ => SocketAddr::new(proxy.ip(), port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy() -> SocketAddr {
        "203.0.113.5:1080".parse().expect("адрес")
    }

    #[test]
    fn a_named_relay_is_taken_at_its_word() {
        let bound = SocketAddress::ip("198.51.100.9".parse().expect("адрес"), 5555);
        assert_eq!(
            relay_address(&bound, proxy()),
            "198.51.100.9:5555".parse().expect("адрес")
        );
    }

    #[test]
    fn an_unspecified_relay_means_the_proxy_itself() {
        // `0.0.0.0` в ответе означает «туда же, куда и TCP»; слать датаграммы
        // по этому адресу буквально — значит слать их в никуда.
        let bound = SocketAddress::ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5555);
        assert_eq!(
            relay_address(&bound, proxy()),
            "203.0.113.5:5555".parse().expect("адрес")
        );
    }

    #[test]
    fn a_relay_named_by_domain_falls_back_to_the_proxy() {
        // Имя указывает на ту же машину, к которой мы уже подключены, — а её
        // адрес у нас есть и он заведомо достижим.
        let bound = SocketAddress::domain("proxy.example.com", 5555);
        assert_eq!(
            relay_address(&bound, proxy()),
            "203.0.113.5:5555".parse().expect("адрес")
        );
    }

    #[test]
    fn a_zero_port_falls_back_to_the_proxy_port() {
        let bound = SocketAddress::ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        assert_eq!(relay_address(&bound, proxy()).port(), 1080);
    }
}
