//! Настройка эндпойнта quinn и параметров соединения.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use penguin_proto::dialer::Dialer;
use quinn::congestion::BbrConfig;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, EndpointConfig, TransportConfig, VarInt};

use super::hop::PortHopper;
use super::obfs::Obfuscator;
#[cfg(feature = "obfs-salamander")]
use super::obfs::salamander::Salamander;
use super::socket::HysteriaSocket;
use crate::config::{Hysteria2Config, ObfsConfig};
use crate::congestion::brutal::{BrutalConfig, BrutalRate};
use crate::error::{Hysteria2Error, Hysteria2Result};
use penguin_transport::tls::{ALPN_H3, client_config as tls_client_config};

/// Установленное соединение QUIC вместе с его эндпойнтом.
///
/// Эндпойнт хранится рядом не для красоты: он владеет задачей ввода-вывода, и
/// как только последняя ссылка на него исчезает, соединение умирает вместе с
/// ней.
pub struct QuicTransport {
    /// Эндпойнт.
    pub endpoint: Endpoint,
    /// Соединение с сервером.
    pub connection: quinn::Connection,
    /// Скорость Brutal, если он используется. Через неё ответ сервера
    /// опускает предел после аутентификации.
    pub brutal_rate: Option<BrutalRate>,
}

/// Поднимает соединение QUIC с сервером.
///
/// Сокет берётся у [`Dialer`], а не открывается здесь. Это не стилистика:
/// TUN перехватывает весь трафик машины, и сокет, открытый обычным способом,
/// отправил бы пакеты в собственный, ещё не поднятый тоннель.
pub async fn connect(
    config: &Hysteria2Config,
    dialer: &dyn Dialer,
    server: SocketAddr,
    server_name: &str,
) -> Hysteria2Result<QuicTransport> {
    let obfs = build_obfuscator(config);
    let hop = PortHopper::new(config.endpoint()?.ports, config.hop_interval());

    // Локальный адрес того же семейства, что и удалённый: сокет IPv4 до
    // сервера IPv6 не достучится.
    let local = match server.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let udp = dialer
        .bind_udp(local)
        .await
        .map_err(|e| Hysteria2Error::Quic(e.to_string()))?;

    let overhead = obfs.as_ref().map_or(0, |o| o.overhead());
    let endpoint_config = endpoint_config(overhead)?;

    let endpoint = if obfs.is_some() || hop.is_some() {
        let socket = HysteriaSocket::new(Arc::new(udp), server, obfs, hop);
        #[cfg(feature = "obfs-gecko")]
        let socket = if matches!(config.obfs, Some(ObfsConfig::Salamander { .. })) {
            socket.with_gecko()
        } else {
            socket
        };
        Endpoint::new_with_abstract_socket(
            endpoint_config,
            None,
            Arc::new(socket),
            Arc::new(quinn::TokioRuntime),
        )
    } else {
        // Быстрый путь: обычный сокет quinn со всей аппаратной поддержкой.
        let std_socket = udp
            .into_std()
            .map_err(|e| Hysteria2Error::Quic(e.to_string()))?;
        Endpoint::new(
            endpoint_config,
            None,
            std_socket,
            Arc::new(quinn::TokioRuntime),
        )
    }
    .map_err(|e| Hysteria2Error::Quic(format!("не удалось создать эндпойнт: {e}")))?;

    let (client_config, brutal_rate) = client_config(config)?;

    let connection = endpoint
        .connect_with(client_config, server, server_name)
        .map_err(|e| Hysteria2Error::Quic(format!("не удалось начать подключение: {e}")))?
        .await
        .map_err(|e| Hysteria2Error::Quic(format!("рукопожатие не завершилось: {e}")))?;

    tracing::debug!(
        server = %server,
        name = server_name,
        rtt_ms = connection.rtt().as_millis() as u64,
        "соединение QUIC установлено"
    );

    Ok(QuicTransport {
        endpoint,
        connection,
        brutal_rate,
    })
}

/// Настройки эндпойнта с поправкой на обфускацию.
fn endpoint_config(obfs_overhead: usize) -> Hysteria2Result<EndpointConfig> {
    let mut endpoint_config = EndpointConfig::default();

    if obfs_overhead > 0 {
        // Обфускация удлиняет пакет, а путевой MTU от этого не растёт. Если
        // не уменьшить объявленный размер, пакет на выходе окажется больше
        // MTU и начнёт дробиться маршрутизаторами — что для QUIC равносильно
        // потере.
        let default = endpoint_config.get_max_udp_payload_size() as usize;
        let reduced = default.saturating_sub(obfs_overhead).max(1200) as u16;
        endpoint_config
            .max_udp_payload_size(reduced)
            .map_err(|e| Hysteria2Error::config(format!("размер датаграммы: {e}")))?;
    }

    Ok(endpoint_config)
}

/// Настройки клиента: TLS плюс параметры транспорта.
fn client_config(config: &Hysteria2Config) -> Hysteria2Result<(ClientConfig, Option<BrutalRate>)> {
    // ALPN — `h3` и только он: сервер Hysteria 2 обязан выглядеть обычным
    // сервером HTTP/3, и любое другое значение выдало бы его первым же
    // пакетом рукопожатия.
    let crypto = tls_client_config(&config.tls, &[ALPN_H3])?;
    let crypto = QuicClientConfig::try_from(crypto)
        .map_err(|e| Hysteria2Error::config(format!("TLS не годится для QUIC: {e}")))?;

    let mut client_config = ClientConfig::new(Arc::new(crypto));
    let (transport, brutal_rate) = transport_config(config)?;
    client_config.transport_config(Arc::new(transport));

    Ok((client_config, brutal_rate))
}

/// Параметры транспорта: окна, таймауты, управление перегрузкой.
fn transport_config(
    config: &Hysteria2Config,
) -> Hysteria2Result<(TransportConfig, Option<BrutalRate>)> {
    let mut transport = TransportConfig::default();
    let quic = &config.quic;

    transport.max_idle_timeout(Some(
        Duration::from_secs(quic.max_idle_timeout_secs.max(1))
            .try_into()
            .map_err(|_| Hysteria2Error::config("слишком большой max_idle_timeout"))?,
    ));

    // Проба живости нужна не только против разрыва по тишине: трансляция
    // адресов у провайдера забывает соединение за десятки секунд, и после
    // этого ответы сервера просто некуда доставить.
    transport.keep_alive_interval(Some(Duration::from_secs(quic.keep_alive_secs.max(1))));

    transport
        .stream_receive_window(VarInt::from_u64(quic.stream_receive_window).unwrap_or(VarInt::MAX));
    transport.receive_window(VarInt::from_u64(quic.conn_receive_window).unwrap_or(VarInt::MAX));
    transport.send_window(quic.conn_receive_window);

    // UDP приложения едет датаграммами QUIC. Без буфера приёма quinn
    // отказывается их принимать вовсе.
    transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    transport.datagram_send_buffer_size(4 * 1024 * 1024);

    // Управление перегрузкой. Brutal работает, только когда скорость канала
    // названа: держать заданную скорость, не зная её, невозможно. Без неё
    // остаётся BBR — он хотя бы не рушится от потерь так, как Cubic.
    let brutal_rate = match config.bandwidth.up_bps()? {
        Some(bits) if bits > 0 => {
            let brutal = BrutalConfig::from_bits_per_second(bits);
            let rate = brutal.rate.clone();
            transport.congestion_controller_factory(Arc::new(brutal));
            tracing::debug!(mbps = bits / 1_000_000, "управление перегрузкой: Brutal");
            Some(rate)
        }
        _ => {
            transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
            tracing::debug!("скорость отдачи не задана — управление перегрузкой: BBR");
            None
        }
    };

    Ok((transport, brutal_rate))
}

/// Собирает обфускатор по настройкам.
fn build_obfuscator(config: &Hysteria2Config) -> Option<Arc<dyn Obfuscator>> {
    match &config.obfs {
        #[cfg(feature = "obfs-salamander")]
        Some(ObfsConfig::Salamander { password }) => Some(Arc::new(Salamander::new(password))),
        #[cfg(not(feature = "obfs-salamander"))]
        Some(ObfsConfig::Salamander { .. }) => {
            tracing::error!("клиент собран без поддержки Salamander — обфускация не применяется");
            None
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Bandwidth, QuicConfig, TlsConfig};

    fn config() -> Hysteria2Config {
        Hysteria2Config {
            server: "example.com:443".to_owned(),
            password: "secret".to_owned(),
            tls: TlsConfig::default(),
            obfs: None,
            bandwidth: Bandwidth::default(),
            quic: QuicConfig::default(),
            hop_interval_secs: 30,
            fast_open: false,
        }
    }

    #[test]
    fn bandwidth_selects_brutal() {
        let mut config = config();
        config.bandwidth.up = Some("100 mbps".to_owned());
        let (_, rate) = transport_config(&config).expect("собирается");
        let rate = rate.expect("Brutal включён");
        assert_eq!(rate.get(), 12_500_000);
    }

    #[test]
    fn no_bandwidth_falls_back_to_bbr() {
        // Держать заданную скорость, не зная её, невозможно.
        let (_, rate) = transport_config(&config()).expect("собирается");
        assert!(rate.is_none());
    }

    #[test]
    fn obfuscation_shrinks_the_datagram() {
        let plain = endpoint_config(0)
            .expect("собирается")
            .get_max_udp_payload_size();
        let obfuscated = endpoint_config(8)
            .expect("собирается")
            .get_max_udp_payload_size();
        // Иначе обфусцированный пакет перестанет помещаться в путевой MTU.
        assert!(obfuscated < plain);
        assert!(obfuscated >= 1200, "нельзя опускаться ниже минимума QUIC");
    }

    #[test]
    fn client_config_builds() {
        client_config(&config()).expect("собирается");
    }

    #[test]
    fn salamander_is_built_from_config() {
        let mut config = config();
        assert!(build_obfuscator(&config).is_none());
        config.obfs = Some(ObfsConfig::Salamander {
            password: "key".to_owned(),
        });
        let obfs = build_obfuscator(&config).expect("обфускатор собран");
        assert_eq!(obfs.overhead(), 8);
    }
}
