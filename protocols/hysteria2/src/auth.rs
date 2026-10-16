//! Аутентификация запросом POST /auth поверх HTTP/3 и разбор ответа 233.
//!
//! Здесь и живёт главная хитрость протокола. Сервер Hysteria 2 — это
//! настоящий сервер HTTP/3: на любой запрос без верных учётных данных он
//! отвечает так же, как ответил бы обычный веб-сервер. Активный пробник,
//! постучавшийся на порт, видит веб-сайт, а не прокси.
//!
//! Пропуском служит запрос с заголовком `Hysteria-Auth`. Успех — код **233**,
//! а не 200: 200 сервер может вернуть и на обычный запрос, и тогда клиент
//! принял бы за свой сервер чужой.
//!
//! ```text
//! клиент                                   сервер
//!   │ POST /auth  Host: hysteria              │
//!   │ Hysteria-Auth: <пароль>                 │
//!   │ Hysteria-CC-RX: <приём, Б/с>            │
//!   │ Hysteria-Padding: <мусор>               ├──►
//!   │                                         │
//!   │                     233                 │
//!   │                     Hysteria-UDP: true  │
//!   │                     Hysteria-CC-RX: ... │
//!   │◄────────────────────────────────────────┤
//! ```

use penguin_transport::h3::{Connection, Request};

use crate::error::{Hysteria2Error, Hysteria2Result};
use crate::frame::padding::Padding;

/// Значение заголовка `Host`. Задано протоколом, не адресом сервера.
pub const AUTH_HOST: &str = "hysteria";

/// Путь запроса аутентификации.
pub const AUTH_PATH: &str = "/auth";

/// Код успешной аутентификации.
///
/// Не 200: обычный веб-сервер отвечает двумястами на что угодно, и клиент
/// принял бы за свой первый попавшийся сайт.
pub const STATUS_AUTH_OK: u16 = 233;

const HEADER_AUTH: &str = "Hysteria-Auth";
const HEADER_CC_RX: &str = "Hysteria-CC-RX";
const HEADER_PADDING: &str = "Hysteria-Padding";
const HEADER_UDP: &str = "Hysteria-UDP";

/// Что ответил сервер.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    /// Сервер согласен проксировать UDP.
    pub udp_enabled: bool,
    /// Предел скорости приёма сервера.
    pub rate: ServerRate,
}

/// Скорость приёма сервера из заголовка `Hysteria-CC-RX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRate {
    /// Сервер назвал предел в байтах в секунду. Слать быстрее бессмысленно.
    Limited(u64),
    /// `0` — сервер не ограничивает.
    Unlimited,
    /// `auto` — сервер просит клиента разбираться самому, обычным управлением
    /// перегрузкой.
    Auto,
    /// Заголовка нет или он не разбирается.
    Unknown,
}

/// Проходит аутентификацию.
///
/// `rx_bytes_per_second` — сколько клиент готов принимать. Ноль означает «не
/// знаю»; тогда сервер выбирает управление перегрузкой сам.
pub async fn authenticate(
    connection: &Connection,
    password: &str,
    rx_bytes_per_second: u64,
) -> Hysteria2Result<AuthResponse> {
    let mut stream = connection
        .send_request(&auth_request(password, rx_bytes_per_second))
        .await
        .map_err(|e| Hysteria2Error::Auth(format!("запрос не отправлен: {e}")))?;

    stream
        .finish()
        .map_err(|e| Hysteria2Error::Auth(format!("не удалось закрыть поток запроса: {e}")))?;

    let response = stream
        .response()
        .await
        .map_err(|e| Hysteria2Error::Auth(format!("ответ не получен: {e}")))?;

    let status = response.status();
    if status != STATUS_AUTH_OK {
        return Err(Hysteria2Error::AuthRejected { status });
    }

    let udp_enabled = response
        .header(HEADER_UDP)
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));

    let rate = response
        .header(HEADER_CC_RX)
        .map_or(ServerRate::Unknown, parse_server_rate);

    tracing::debug!(?rate, udp = udp_enabled, "аутентификация пройдена");
    Ok(AuthResponse { udp_enabled, rate })
}

/// Запрос `POST /auth`.
fn auth_request(password: &str, rx_bytes_per_second: u64) -> Request {
    Request::new("POST", AUTH_HOST, AUTH_PATH)
        .header(HEADER_AUTH, password)
        .header(HEADER_CC_RX, rx_bytes_per_second.to_string())
        .header(HEADER_PADDING, Padding::AUTH_REQUEST.generate())
}

/// Разбирает значение `Hysteria-CC-RX` из ответа сервера.
fn parse_server_rate(raw: &str) -> ServerRate {
    let raw = raw.trim();
    if raw.eq_ignore_ascii_case("auto") {
        return ServerRate::Auto;
    }
    match raw.parse::<u64>() {
        Ok(0) => ServerRate::Unlimited,
        Ok(rate) => ServerRate::Limited(rate),
        Err(_) => ServerRate::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use penguin_transport::h3::qpack::field;

    use super::*;

    #[test]
    fn parses_server_rate() {
        assert_eq!(
            parse_server_rate("12500000"),
            ServerRate::Limited(12_500_000)
        );
        assert_eq!(parse_server_rate("0"), ServerRate::Unlimited);
        assert_eq!(parse_server_rate("auto"), ServerRate::Auto);
        assert_eq!(parse_server_rate("AUTO"), ServerRate::Auto);
        assert_eq!(parse_server_rate(" 42 "), ServerRate::Limited(42));
        assert_eq!(parse_server_rate("быстро"), ServerRate::Unknown);
        assert_eq!(parse_server_rate(""), ServerRate::Unknown);
    }

    #[test]
    fn success_code_is_233_not_200() {
        assert_eq!(STATUS_AUTH_OK, 233);
        assert_ne!(STATUS_AUTH_OK, 200);
    }

    #[test]
    fn request_carries_the_expected_headers() {
        let block = auth_request("hunter2", 12_500_000).encode();
        let fields: Vec<(String, String)> = field::decode(&block, usize::MAX)
            .expect("разбирается")
            .into_iter()
            .map(|f| {
                let text = |b: Vec<u8>| String::from_utf8(b).expect("текст");
                (text(f.name), text(f.value))
            })
            .collect();
        let get = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };

        assert_eq!(get(":method"), Some("POST"));
        assert_eq!(get(":scheme"), Some("https"));
        assert_eq!(get(":authority"), Some(AUTH_HOST));
        assert_eq!(get(":path"), Some("/auth"));
        assert_eq!(get("hysteria-auth"), Some("hunter2"));
        assert_eq!(get("hysteria-cc-rx"), Some("12500000"));

        let padding = get("hysteria-padding").expect("дополнение есть");
        assert!((256..=2048).contains(&padding.len()));
    }
}
