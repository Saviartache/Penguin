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

use bytes::Bytes;
use h3::client::SendRequest;
use http::{Method, Request};

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

/// Отправитель запросов HTTP/3 поверх соединения quinn.
pub type H3SendRequest = SendRequest<h3_quinn::OpenStreams, Bytes>;

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
    send_request: &mut H3SendRequest,
    password: &str,
    rx_bytes_per_second: u64,
) -> Hysteria2Result<AuthResponse> {
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("https://{AUTH_HOST}{AUTH_PATH}"))
        .header(HEADER_AUTH, password)
        .header(HEADER_CC_RX, rx_bytes_per_second.to_string())
        .header(HEADER_PADDING, Padding::AUTH_REQUEST.generate())
        .body(())
        .map_err(|e| Hysteria2Error::Auth(format!("не удалось собрать запрос: {e}")))?;

    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|e| Hysteria2Error::Auth(format!("запрос не отправлен: {e}")))?;

    // Тела у запроса нет, но поток закрыть надо: пока он открыт, сервер ждёт
    // продолжения и ответа не шлёт.
    stream
        .finish()
        .await
        .map_err(|e| Hysteria2Error::Auth(format!("не удалось закрыть поток запроса: {e}")))?;

    let response = stream
        .recv_response()
        .await
        .map_err(|e| Hysteria2Error::Auth(format!("ответ не получен: {e}")))?;

    let status = response.status().as_u16();
    if status != STATUS_AUTH_OK {
        // Сюда попадает и настоящий веб-сервер, случайно оказавшийся по
        // этому адресу, и наш сервер с неверным паролем. Для пользователя
        // разница невелика — в обоих случаях повторять бессмысленно.
        return Err(Hysteria2Error::AuthRejected { status });
    }

    let headers = response.headers();
    let udp_enabled = headers
        .get(HEADER_UDP)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));

    let rate = headers
        .get(HEADER_CC_RX)
        .and_then(|v| v.to_str().ok())
        .map_or(ServerRate::Unknown, parse_server_rate);

    tracing::debug!(?rate, udp = udp_enabled, "аутентификация пройдена");
    Ok(AuthResponse { udp_enabled, rate })
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
        // 200 вернёт любой веб-сервер; принять его за свой — значит слить
        // трафик неизвестно куда.
        assert_eq!(STATUS_AUTH_OK, 233);
        assert_ne!(STATUS_AUTH_OK, 200);
    }

    #[test]
    fn request_carries_the_expected_headers() {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("https://{AUTH_HOST}{AUTH_PATH}"))
            .header(HEADER_AUTH, "hunter2")
            .header(HEADER_CC_RX, "12500000")
            .header(HEADER_PADDING, Padding::AUTH_REQUEST.generate())
            .body(())
            .expect("собирается");

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri().path(), "/auth");
        assert_eq!(request.uri().host(), Some(AUTH_HOST));
        assert_eq!(request.headers()[HEADER_AUTH], "hunter2");

        let padding = request.headers()[HEADER_PADDING].to_str().expect("текст");
        assert!((256..=2048).contains(&padding.len()));
    }
}
