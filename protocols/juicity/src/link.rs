//! Одно соединение QUIC: рукопожатие, опознание, счёт потоков.
//!
//! `quinn` не показывает оставшуюся ёмкость потоков, а `open_bi` при
//! исчерпании ждёт. Поэтому по спецификации после [`MAX_STREAMS`] потоков
//! соединение новых не выдаёт, и следующий поток заводит новое соединение.
//! Сокет выдаёт `Dialer`: иначе TUN перехватит собственный трафик.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use penguin_core::uuid::Uuid;
use penguin_proto::dialer::Dialer;
use penguin_transport::tls::client_config as tls_client_config;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, EndpointConfig, TransportConfig, VarInt};

use crate::config::JuicityConfig;
use crate::error::{JuicityError, JuicityResult};
use crate::frame::auth;

/// Сервер не понял, что мы прислали.
pub const PROTOCOL_ERROR: u64 = 0xffff_fff0;
/// Сервер не признал UUID и пароль.
pub const AUTH_FAILED: u64 = 0xffff_fff1;
/// Опознание не пришло вовремя.
pub const AUTH_TIMEOUT: u64 = 0xffff_fff2;
/// Команда не та.
pub const BAD_COMMAND: u64 = 0xffff_fff3;

/// Потоков на соединение: сервер обязан разрешать не меньше тридцати (спецификация).
pub const MAX_STREAMS: u32 = 30;

/// Наибольшее окно приёма потока, как у эталона (начальное не задаём: `quinn` окно не растит).
const MAX_STREAM_WINDOW: u64 = 32 * 1024 * 1024;

/// Наибольшее окно приёма всего соединения.
const MAX_CONNECTION_WINDOW: u64 = 64 * 1024 * 1024;

/// Как часто напоминать о себе.
const KEEP_ALIVE: Duration = Duration::from_secs(5);

/// Сколько соединение живёт без единого пакета.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Соединение QUIC вместе с эндпойнтом; потоки держат [`Link`], пока живы.
pub struct Link {
    _endpoint: Endpoint,
    connection: quinn::Connection,
    opened: AtomicU32,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("opened", &self.opened.load(Ordering::Relaxed))
            .field("closed", &self.connection.close_reason().is_some())
            .finish()
    }
}

impl Link {
    /// Поднимает соединение и представляется серверу.
    pub async fn connect(
        config: &JuicityConfig,
        dialer: &dyn Dialer,
        server: SocketAddr,
        server_name: &str,
    ) -> JuicityResult<Arc<Self>> {
        let local = match server.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let udp = dialer
            .bind_udp(local)
            .await
            .map_err(|e| JuicityError::disconnected(e.to_string()))?
            .into_std()
            .map_err(|e| JuicityError::disconnected(e.to_string()))?;

        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            None,
            udp,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| JuicityError::disconnected(format!("не удалось создать эндпойнт: {e}")))?;

        let connection = endpoint
            .connect_with(client_config(config)?, server, server_name)
            .map_err(|e| JuicityError::disconnected(format!("не удалось начать подключение: {e}")))?
            .await
            .map_err(classify)?;

        tracing::debug!(
            %server,
            name = server_name,
            rtt_ms = connection.rtt().as_millis() as u64,
            "соединение QUIC установлено"
        );

        let link = Arc::new(Self {
            _endpoint: endpoint,
            connection,
            opened: AtomicU32::new(0),
        });
        link.authenticate(&config.uuid, &config.password).await?;
        Ok(link)
    }

    /// Годится ли соединение под новый поток.
    pub fn usable(&self) -> bool {
        self.opened.load(Ordering::Relaxed) < MAX_STREAMS
            && self.connection.close_reason().is_none()
    }

    /// Открывает двусторонний поток; счётчик растёт и при неудаче.
    pub async fn open(&self) -> JuicityResult<(quinn::SendStream, quinn::RecvStream)> {
        self.opened.fetch_add(1, Ordering::Relaxed);
        self.connection.open_bi().await.map_err(classify)
    }

    /// Представляется серверу односторонним потоком; ответа нет, запросы можно слать сразу.
    async fn authenticate(&self, uuid: &Uuid, password: &str) -> JuicityResult<()> {
        let mut token = [0u8; auth::TOKEN_LEN];
        self.connection
            .export_keying_material(&mut token, &auth::label(uuid), password.as_bytes())
            .map_err(|_| JuicityError::malformed("соединение не отдаёт ключевой материал"))?;

        let mut send = self.connection.open_uni().await.map_err(classify)?;
        send.write_all(&auth::request(uuid, &token))
            .await
            .map_err(|e| JuicityError::disconnected(format!("опознание не ушло: {e}")))?;

        // Эталон держит поток открытым ради «скрытого» режима, которого у нас нет.
        send.finish()
            .map_err(|e| JuicityError::disconnected(format!("опознание не закрылось: {e}")))?;
        Ok(())
    }
}

/// Переводит ошибку соединения; код `0xfffffff1` — неверный пароль, повторять нельзя.
pub fn classify(err: quinn::ConnectionError) -> JuicityError {
    if let quinn::ConnectionError::ApplicationClosed(closed) = &err {
        return match closed.error_code.into_inner() {
            AUTH_FAILED => JuicityError::AuthRejected,
            AUTH_TIMEOUT => JuicityError::disconnected("сервер не дождался опознания"),
            PROTOCOL_ERROR | BAD_COMMAND => {
                JuicityError::malformed(format!("сервер закрыл соединение: {closed}"))
            }
            _ => JuicityError::disconnected(closed.to_string()),
        };
    }
    JuicityError::disconnected(err.to_string())
}

/// Настройки клиента: TLS плюс параметры транспорта.
fn client_config(config: &JuicityConfig) -> JuicityResult<ClientConfig> {
    let crypto = tls_client_config(&config.tls, config.default_alpn())?;
    let crypto = QuicClientConfig::try_from(crypto)
        .map_err(|e| JuicityError::config(format!("TLS не годится для QUIC: {e}")))?;

    let mut client = ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(transport_config()?));
    Ok(client)
}

/// Окна, сроки и BBR — как у эталона.
fn transport_config() -> JuicityResult<TransportConfig> {
    let mut transport = TransportConfig::default();

    transport.stream_receive_window(VarInt::from_u64(MAX_STREAM_WINDOW).unwrap_or(VarInt::MAX));
    transport
        .receive_window(VarInt::from_u64(MAX_CONNECTION_WINDOW).unwrap_or(VarInt::MAX))
        .send_window(MAX_CONNECTION_WINDOW);
    transport.datagram_receive_buffer_size(None);

    let idle = VarInt::from_u64(IDLE_TIMEOUT.as_millis().min(u128::from(u32::MAX)) as u64)
        .map_err(|_| JuicityError::config("слишком большое время жизни соединения"))?;
    transport.max_idle_timeout(Some(idle.into()));
    transport.keep_alive_interval(Some(KEEP_ALIVE));

    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Ok(transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn config() -> JuicityConfig {
        JuicityConfig {
            server: "example.com:443".to_owned(),
            uuid: TEXT.parse().expect("разбирается"),
            password: "secret".to_owned(),
            ..JuicityConfig::default()
        }
    }

    #[test]
    fn the_whole_client_config_builds() {
        client_config(&config()).expect("собирается");
    }

    #[test]
    fn the_client_announces_h3() {
        let config = config();
        let crypto = tls_client_config(&config.tls, config.default_alpn()).expect("собирается");
        assert_eq!(crypto.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn a_refused_password_is_told_apart_from_a_broken_link() {
        let refused = classify(quinn::ConnectionError::ApplicationClosed(
            quinn::ApplicationClose {
                error_code: VarInt::from_u64(AUTH_FAILED).expect("помещается"),
                reason: bytes::Bytes::new(),
            },
        ));
        assert!(matches!(refused, JuicityError::AuthRejected));

        let other = classify(quinn::ConnectionError::TimedOut);
        assert!(matches!(other, JuicityError::Disconnected(_)));
    }

    #[test]
    fn some_other_application_code_is_a_broken_link() {
        let closed = classify(quinn::ConnectionError::ApplicationClosed(
            quinn::ApplicationClose {
                error_code: VarInt::from_u32(7),
                reason: bytes::Bytes::new(),
            },
        ));
        assert!(matches!(closed, JuicityError::Disconnected(_)));
    }

    #[test]
    fn the_stream_limit_is_the_one_the_spec_names() {
        assert_eq!(MAX_STREAMS, 30);
    }
}
