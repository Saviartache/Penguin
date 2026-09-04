//! Соединение QUIC до сервера.
//!
//! Устроено так же, как у Hysteria 2, и по той же причине: сокет берётся у
//! [`Dialer`], а не открывается здесь. TUN перехватывает весь трафик машины, и
//! сокет, открытый обычным способом, отправил бы пакеты в собственный, ещё не
//! поднятый тоннель.
//!
//! Отличий от Hysteria 2 два, и оба — в сторону простоты: ни обфускации, ни
//! смены порта у TUIC нет, поэтому берётся обычный сокет `quinn` со всей
//! аппаратной поддержкой, какую даёт ядро.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use penguin_proto::dialer::Dialer;
use penguin_transport::tls::client_config as tls_client_config;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, EndpointConfig, TransportConfig, VarInt};

use crate::config::{Congestion, TuicConfig};
use crate::error::{TuicError, TuicResult};

/// Установленное соединение вместе с его эндпойнтом.
///
/// Эндпойнт хранится рядом не для красоты: он владеет задачей ввода-вывода, и
/// как только последняя ссылка на него исчезает, соединение умирает вместе с
/// ней.
pub struct QuicTransport {
    /// Эндпойнт.
    pub endpoint: Endpoint,
    /// Соединение с сервером.
    pub connection: quinn::Connection,
}

/// Поднимает соединение QUIC с сервером.
pub async fn connect(
    config: &TuicConfig,
    dialer: &dyn Dialer,
    server: SocketAddr,
    server_name: &str,
) -> TuicResult<QuicTransport> {
    // Локальный адрес того же семейства, что и удалённый: сокет IPv4 до
    // сервера IPv6 не достучится.
    let local = match server.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let udp = dialer
        .bind_udp(local)
        .await
        .map_err(|e| TuicError::Disconnected(e.to_string()))?
        .into_std()
        .map_err(|e| TuicError::Disconnected(e.to_string()))?;

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        None,
        udp,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| TuicError::Disconnected(format!("не удалось создать эндпойнт: {e}")))?;

    let connection = endpoint
        .connect_with(client_config(config)?, server, server_name)
        .map_err(|e| TuicError::Disconnected(format!("не удалось начать подключение: {e}")))?
        .await
        .map_err(|e| TuicError::Disconnected(format!("рукопожатие не завершилось: {e}")))?;

    tracing::debug!(
        %server,
        name = server_name,
        rtt_ms = connection.rtt().as_millis() as u64,
        "соединение QUIC установлено"
    );

    Ok(QuicTransport {
        endpoint,
        connection,
    })
}

/// Настройки клиента: TLS плюс параметры транспорта.
fn client_config(config: &TuicConfig) -> TuicResult<ClientConfig> {
    let crypto = tls_client_config(&config.tls, config.default_alpn())?;
    let crypto = QuicClientConfig::try_from(crypto)
        .map_err(|e| TuicError::config(format!("TLS не годится для QUIC: {e}")))?;

    let mut client = ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(transport_config(config)?));
    Ok(client)
}

/// Окна, сроки и управление перегрузкой.
fn transport_config(config: &TuicConfig) -> TuicResult<TransportConfig> {
    let mut transport = TransportConfig::default();

    // Датаграммы нужны и для полезного трафика, и для напоминаний о себе.
    // Без явного размера окна quinn их принимать не станет.
    transport.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
    transport.datagram_send_buffer_size(DATAGRAM_BUFFER);

    let idle = VarInt::from_u64(config.idle().as_millis().min(u128::from(u32::MAX)) as u64)
        .map_err(|_| TuicError::config("слишком большое время жизни соединения"))?;
    transport.max_idle_timeout(Some(idle.into()));

    // Своё напоминание протокол шлёт сам, командой `Heartbeat`: пусть его
    // видит и сервер, а не только QUIC. Поэтому встроенное выключено.
    transport.keep_alive_interval(None);

    match config.congestion {
        Congestion::Bbr => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
        Congestion::Cubic => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
        Congestion::NewReno => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
    }

    Ok(transport)
}

/// Сколько байт датаграмм держать в очереди в каждую сторону.
const DATAGRAM_BUFFER: usize = 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn config() -> TuicConfig {
        TuicConfig {
            server: "example.com:443".to_owned(),
            uuid: TEXT.parse().expect("разбирается"),
            password: "secret".to_owned(),
            heartbeat_secs: 10,
            idle_secs: 30,
            ..TuicConfig::default()
        }
    }

    #[test]
    fn every_congestion_controller_builds() {
        for congestion in [Congestion::Bbr, Congestion::Cubic, Congestion::NewReno] {
            let config = TuicConfig {
                congestion,
                ..config()
            };
            transport_config(&config).expect("собирается");
        }
    }

    #[test]
    fn the_client_announces_h3() {
        // Сервер TUIC обязан выглядеть обычным сервером HTTP/3: любое другое
        // объявление выдало бы его первым же пакетом рукопожатия.
        let config = config();
        let crypto = tls_client_config(&config.tls, config.default_alpn()).expect("собирается");
        assert_eq!(crypto.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn the_whole_client_config_builds() {
        client_config(&config()).expect("собирается");
    }
}
