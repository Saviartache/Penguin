//! Рукопожатие WebSocket: обычный запрос HTTP с просьбой сменить протокол.
//!
//! ```text
//! GET /path HTTP/1.1
//! Host: example.com
//! Upgrade: websocket
//! Connection: Upgrade
//! Sec-WebSocket-Key: <16 случайных байт в base64>
//! Sec-WebSocket-Version: 13
//!
//! HTTP/1.1 101 Switching Protocols
//! Upgrade: websocket
//! Connection: Upgrade
//! Sec-WebSocket-Accept: <base64(SHA-1(ключ + GUID))>
//! ```
//!
//! Проверка `Sec-WebSocket-Accept` — не формальность и не защита: GUID
//! известен всем. Она отвечает на другой вопрос — тот ли это собеседник,
//! который прочитал наш запрос, а не промежуточный узел, кэш или прокси,
//! ответивший заготовкой. Без неё соединение с кэширующим узлом выглядело бы
//! установленным, а данные уходили бы в никуда.
//!
//! Разбор ответа — чистая функция над строкой, и проверяется он без сети.

use penguin_core::base64;
use ring::digest;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::deadline;
use crate::error::{TransportError, TransportResult};

/// Постоянная из RFC 6455, §1.3. Секретом не является.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Наибольший заголовок ответа, который мы согласны прочитать.
///
/// Сервер, отвечающий бесконечным заголовком, иначе набивал бы нам память,
/// пока не кончится.
const MAX_HEAD: usize = 8 * 1024;

/// Из чего складывается запрос.
#[derive(Debug, Clone)]
pub struct Request {
    /// Значение заголовка `Host`.
    ///
    /// Отдельно от адреса сервера: у прокси за общим входом это имя решает,
    /// какому серверу достанется соединение, и совпадать с адресом оно не
    /// обязано.
    pub host: String,
    /// Путь вместе с запросом: `/ws?ed=2048`.
    pub path: String,
    /// Что дописать в заголовки.
    pub headers: Vec<(String, String)>,
}

impl Request {
    /// Запрос с путём и именем узла.
    pub fn new(host: impl Into<String>, path: impl Into<String>) -> Self {
        let path = path.into();
        Self {
            host: host.into(),
            // Пустой путь превратил бы строку запроса в `GET  HTTP/1.1`, и
            // ответом на это будет 400 — то есть «прокси не работает».
            path: if path.is_empty() {
                "/".to_owned()
            } else {
                path
            },
            headers: Vec::new(),
        }
    }
}

/// Собирает текст запроса.
///
/// Отдельно от отправки, чтобы проверять его без сокета.
pub fn request_text(request: &Request, key: &str) -> String {
    let mut text = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n",
        request.path, request.host, key
    );
    for (name, value) in &request.headers {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    text.push_str("\r\n");
    text
}

/// Ответ, который сервер обязан прислать на такой ключ.
pub fn accept_for(key: &str) -> String {
    let digest = digest::digest(
        &digest::SHA1_FOR_LEGACY_USE_ONLY,
        [key, GUID].concat().as_bytes(),
    );
    base64::encode(digest.as_ref())
}

/// Проверяет заголовок ответа.
///
/// `head` — всё до пустой строки, без неё самой.
pub fn check_response(head: &str, key: &str) -> TransportResult<()> {
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| TransportError::malformed("пустой ответ"))?;

    // Именно 101. Двухсотый ответ означает, что на том конце обычный сайт, а
    // не прокси, — самая частая ошибка в пути и в имени узла.
    if !status.contains(" 101") {
        return Err(TransportError::malformed(format!(
            "на смену протокола ответили `{}`",
            status.trim()
        )));
    }

    let expected = accept_for(key);
    let mut accept = None;
    let mut upgraded = false;

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        // Имена заголовков регистронезависимы, и сервера этим пользуются.
        match name.trim().to_ascii_lowercase().as_str() {
            "sec-websocket-accept" => accept = Some(value.to_owned()),
            "upgrade" => upgraded = value.eq_ignore_ascii_case("websocket"),
            _ => {}
        }
    }

    if !upgraded {
        return Err(TransportError::malformed(
            "в ответе нет `Upgrade: websocket`",
        ));
    }
    match accept {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => Err(TransportError::malformed(
            "`Sec-WebSocket-Accept` не сходится: отвечает не тот, кто читал запрос",
        )),
        None => Err(TransportError::malformed(
            "в ответе нет `Sec-WebSocket-Accept`",
        )),
    }
}

/// Случайный ключ запроса: шестнадцать байт в base64.
///
/// Секретом не является — он и уходит открытым текстом. Случайность нужна
/// затем, чтобы ответ нельзя было заготовить заранее.
pub fn new_key() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill(&mut bytes);
    base64::encode(&bytes)
}

/// Проводит рукопожатие и возвращает байты, пришедшие следом за заголовком.
///
/// Хвост возвращается, а не отбрасывается: сервер вправе прислать первый кадр
/// в том же пакете, что и ответ, и выбросить его значило бы потерять начало
/// каждого такого соединения.
pub async fn perform<S>(io: &mut S, request: &Request) -> TransportResult<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = new_key();
    let text = request_text(request, &key);

    deadline::handshake("рукопожатие WebSocket", async {
        io.write_all(text.as_bytes()).await?;
        io.flush().await?;
        read_response(io, &key).await
    })
    .await
}

/// Читает ответ до пустой строки и проверяет его.
async fn read_response<S>(io: &mut S, key: &str) -> TransportResult<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let (head, tail) = read_head(io).await?;
    check_response(&head, key)?;
    Ok(tail)
}

/// Читает заголовок ответа целиком и возвращает его вместе с хвостом.
///
/// Общая часть с [`crate::httpupgrade`]: рукопожатие там то же самое, а
/// проверка ответа — другая.
pub(crate) async fn read_head<S>(io: &mut S) -> TransportResult<(String, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];

    loop {
        if let Some(end) = find_head_end(&buffer) {
            let head = std::str::from_utf8(&buffer[..end])
                .map_err(|_| TransportError::malformed("заголовок ответа не UTF-8"))?
                .to_owned();
            return Ok((head, buffer[end + 4..].to_vec()));
        }
        if buffer.len() > MAX_HEAD {
            return Err(TransportError::malformed(
                "заголовок ответа длиннее восьми килобайт",
            ));
        }

        let read = io.read(&mut chunk).await?;
        if read == 0 {
            return Err(TransportError::disconnected(
                "соединение закрылось на рукопожатии WebSocket",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Где кончается заголовок: позиция перед `\r\n\r\n`.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Пример из RFC 6455, §1.3.
    const RFC_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const RFC_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    #[test]
    fn the_accept_matches_the_rfc_example() {
        // Своя реализация согласится сама с собой при любой ошибке; проверять
        // её надо о чужой ответ.
        assert_eq!(accept_for(RFC_KEY), RFC_ACCEPT);
    }

    #[test]
    fn the_request_says_everything_the_server_expects() {
        let mut request = Request::new("example.com", "/ws");
        request
            .headers
            .push(("X-Свой".to_owned(), "значение".to_owned()));
        let text = request_text(&request, RFC_KEY);

        assert!(text.starts_with("GET /ws HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com\r\n"));
        assert!(text.contains("Upgrade: websocket\r\n"));
        assert!(text.contains("Connection: Upgrade\r\n"));
        assert!(text.contains(&format!("Sec-WebSocket-Key: {RFC_KEY}\r\n")));
        assert!(text.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(text.contains("X-Свой: значение\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn an_empty_path_becomes_a_slash() {
        // `GET  HTTP/1.1` — это 400, то есть «прокси не работает».
        let text = request_text(&Request::new("example.com", ""), RFC_KEY);
        assert!(text.starts_with("GET / HTTP/1.1\r\n"), "{text}");
    }

    #[test]
    fn a_good_response_passes() {
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {RFC_ACCEPT}"
        );
        check_response(&head, RFC_KEY).expect("ответ верный");
    }

    #[test]
    fn header_names_are_case_insensitive() {
        // Сервера пишут их как хотят, и это разрешено.
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             upgrade: WebSocket\r\n\
             SEC-WEBSOCKET-ACCEPT: {RFC_ACCEPT}"
        );
        check_response(&head, RFC_KEY).expect("ответ верный");
    }

    #[test]
    fn an_ordinary_web_page_is_told_apart_from_a_proxy() {
        // Самая частая ошибка настройки — не тот путь: сервер отвечает
        // страницей, и ответ на это должен называть код, а не молчать.
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/html";
        let err = check_response(head, RFC_KEY).expect_err("это не прокси");
        assert!(err.to_string().contains("200"), "{err}");
    }

    #[test]
    fn a_prepared_answer_is_refused() {
        // Узел, ответивший заготовкой, ключа не читал — и `Accept` у него не
        // сойдётся. Без этой проверки соединение с кэшем выглядело бы живым.
        let head = "HTTP/1.1 101 Switching Protocols\r\n\
                    Upgrade: websocket\r\n\
                    Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(check_response(head, RFC_KEY).is_err());
    }

    #[test]
    fn a_response_without_upgrade_is_refused() {
        let head =
            format!("HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: {RFC_ACCEPT}");
        assert!(check_response(&head, RFC_KEY).is_err());
    }

    #[test]
    fn a_response_without_accept_is_refused() {
        let head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket";
        assert!(check_response(head, RFC_KEY).is_err());
    }

    #[test]
    fn every_key_is_different() {
        // Заготовленный ответ проходил бы на постоянном ключе.
        assert_ne!(new_key(), new_key());
        assert_eq!(base64::decode(&new_key()).expect("base64").len(), 16);
    }

    #[test]
    fn the_end_of_the_head_is_found_where_it_is() {
        assert_eq!(find_head_end("HTTP\r\n\r\nданные".as_bytes()), Some(4));
        assert_eq!(find_head_end(b"HTTP\r\n"), None);
    }

    #[tokio::test]
    async fn data_arriving_with_the_response_is_kept() {
        // Сервер вправе прислать первый кадр тем же пакетом. Выбросить его
        // значит потерять начало каждого такого соединения.
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Accept: {RFC_ACCEPT}\r\n\r\nхвост"
        );
        let mut io = std::io::Cursor::new(response.into_bytes());
        let tail = read_response(&mut io, RFC_KEY).await.expect("рукопожатие");
        assert_eq!(tail, "хвост".as_bytes());
    }

    #[tokio::test]
    async fn a_connection_closed_mid_handshake_is_a_disconnect() {
        // Не «сломанный ответ»: обрыв повторяют, а сломанный ответ — нет.
        let mut io = std::io::Cursor::new(b"HTTP/1.1 101 Switching".to_vec());
        let err = read_response(&mut io, RFC_KEY).await.expect_err("обрыв");
        assert!(matches!(err, TransportError::Disconnected(_)), "{err}");
    }
}
