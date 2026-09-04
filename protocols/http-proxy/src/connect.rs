//! Запрос `CONNECT` и разбор ответа прокси.
//!
//! Сборка запроса и разбор ответа — свободные функции без `tokio`: их видно
//! целиком и можно проверить без сети. Ждать умеет только [`perform`].
//!
//! # Что в запросе не написано
//!
//! Ни `User-Agent`, ни `Proxy-Connection`, ни чего-либо ещё сверх обязательного.
//! Каждый лишний заголовок — это примета, по которой соединение отличают от
//! соседнего; отправлять их незачем, а `CONNECT` без них работает у всех.

use penguin_core::address::SocketAddress;
use penguin_transport::deadline;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::basic;
use crate::error::{HttpProxyError, HttpProxyResult};

/// Насколько длинным может быть ответ прокси до пустой строки.
///
/// Восьми килобайт хватает любому разумному ответу с запасом. Предел нужен не
/// ради памяти, а ради того, чтобы разговор с чем-то, что не является прокси,
/// кончался ошибкой, а не бесконечным чтением.
pub const MAX_HEAD: usize = 8 * 1024;

/// Конец заголовков.
const TERMINATOR: &[u8] = b"\r\n\r\n";

/// Собирает запрос.
pub fn request(target: &SocketAddress, credentials: Option<(&str, &str)>) -> String {
    // Адрес назначения — доменом, если он домен: разрешать имя должен прокси,
    // иначе правило «youtube.com в тоннель» теряет смысл на последнем шаге.
    let host = target.to_wire();
    let mut out = format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\n");

    if let Some((username, password)) = credentials {
        out.push_str("Proxy-Authorization: ");
        out.push_str(&basic::header_value(username, password));
        out.push_str("\r\n");
    }

    out.push_str("\r\n");
    out
}

/// Код ответа и строка причины из первой строки.
pub fn parse_status(head: &str) -> HttpProxyResult<(u16, String)> {
    let line = head.lines().next().unwrap_or_default().trim();
    let mut parts = line.splitn(3, ' ');

    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(HttpProxyError::malformed(format!(
            "ответ начинается с `{}`",
            line.chars().take(32).collect::<String>()
        )));
    }

    let status: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| HttpProxyError::malformed(format!("нет кода ответа в `{line}`")))?;

    Ok((status, parts.next().unwrap_or_default().trim().to_owned()))
}

/// Ошибка, соответствующая коду ответа.
///
/// `None` — прокси согласился. Свободная функция с таблицей, потому что от
/// выбора варианта зависит, будет ли `supervisor` повторять попытку: `407` —
/// это неверный пароль, и повторять его бессмысленно.
pub fn outcome(status: u16, message: &str, target: &str) -> Option<HttpProxyError> {
    match status {
        200..=299 => None,
        // 407 — «нужен пароль прокси», 401 шлют те, кто путает его с обычным.
        401 | 407 => Some(HttpProxyError::AuthRejected { status }),
        _ => Some(HttpProxyError::Refused {
            target: target.to_owned(),
            status,
            message: message.to_owned(),
        }),
    }
}

/// Открывает тоннель через прокси.
///
/// Возвращает то, что прокси прислал **после** пустой строки: это уже байты
/// того, к кому он соединил, и выбросить их значило бы съесть приветствие
/// сервера (см. [`crate::stream::Prefixed`]).
pub async fn perform<S>(
    io: &mut S,
    target: &SocketAddress,
    credentials: Option<(&str, &str)>,
) -> HttpProxyResult<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Срок обязателен: прокси, принявший соединение и замолчавший на ответе,
    // иначе держал бы поток приложения вечно — а выглядит это как страница,
    // которая грузится и не загружается.
    deadline::handshake("ответ прокси на CONNECT", async {
        io.write_all(request(target, credentials).as_bytes())
            .await?;
        io.flush().await?;

        let (head, tail) = read_head(io).await?;
        let (status, message) = parse_status(&head)?;

        match outcome(status, &message, &target.to_wire()) {
            Some(err) => Err(err),
            None => Ok(tail),
        }
    })
    .await
}

/// Читает ответ до пустой строки.
///
/// Отдаёт заголовки текстом и остаток пачки, который пришёл вместе с ними.
async fn read_head<S>(io: &mut S) -> HttpProxyResult<(String, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];

    loop {
        // Место конца заголовков ищется с оглядкой назад: разделитель мог
        // прийти разрезанным между двумя пачками.
        let searched = buffer.len().saturating_sub(TERMINATOR.len() - 1);
        let read = io.read(&mut chunk).await?;
        if read == 0 {
            return Err(HttpProxyError::Disconnected(
                "прокси закрыл соединение, не ответив".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);

        if let Some(at) = find(&buffer[searched..], TERMINATOR) {
            let end = searched + at;
            let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
            let tail = buffer.split_off(end + TERMINATOR.len());
            return Ok((head, tail));
        }

        if buffer.len() > MAX_HEAD {
            return Err(HttpProxyError::malformed(format!(
                "ответ длиннее {MAX_HEAD} байт и всё ещё не кончился"
            )));
        }
    }
}

/// Где в срезе встречается образец.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    fn target() -> SocketAddress {
        SocketAddress::domain("example.com", 443)
    }

    #[test]
    fn the_request_names_the_target_twice() {
        // `Host` обязателен в HTTP/1.1, и прокси, придирчивые к нему, есть.
        let request = request(&target(), None);
        assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(request.contains("\r\nHost: example.com:443\r\n"));
        assert!(request.ends_with("\r\n\r\n"));
    }

    #[test]
    fn the_request_carries_nothing_extra() {
        // Каждый лишний заголовок — примета, по которой соединение отличают
        // от соседнего.
        let request = request(&target(), None);
        assert_eq!(request.lines().filter(|line| !line.is_empty()).count(), 2);
    }

    #[test]
    fn credentials_go_into_the_header() {
        let request = request(&target(), Some(("Aladdin", "open sesame")));
        assert!(request.contains("Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));
    }

    #[test]
    fn a_name_stays_a_name_in_the_request() {
        // Разрешить его здесь значило бы отдать прокси адрес из CDN вместо
        // имени, по которому написано правило.
        assert!(
            request(&SocketAddress::domain("youtube.com", 443), None)
                .starts_with("CONNECT youtube.com:443")
        );
    }

    #[test]
    fn a_status_line_parses() {
        let (status, message) =
            parse_status("HTTP/1.1 200 Connection established").expect("разбирается");
        assert_eq!(status, 200);
        assert_eq!(message, "Connection established");

        // Строки причины может не быть вовсе — это законно.
        let (status, message) = parse_status("HTTP/1.0 200").expect("разбирается");
        assert_eq!(status, 200);
        assert!(message.is_empty());
    }

    #[test]
    fn something_that_is_not_http_is_recognised() {
        // На порту сидит SOCKS5: он отвечает байтами, а не строкой.
        assert!(parse_status("\u{5}\u{0}").is_err());
        assert!(parse_status("").is_err());
        assert!(parse_status("HTTP/1.1 не число").is_err());
    }

    #[test]
    fn a_wrong_password_is_told_apart_from_a_refusal() {
        // От этого зависит, будет ли `supervisor` повторять попытку.
        let err = outcome(407, "Proxy Authentication Required", "example.com:443").expect("отказ");
        assert!(matches!(err, HttpProxyError::AuthRejected { .. }));

        let err = outcome(502, "Bad Gateway", "example.com:443").expect("отказ");
        assert!(matches!(err, HttpProxyError::Refused { .. }));

        assert!(outcome(200, "Connection established", "example.com:443").is_none());
        // Прокси вправе ответить любым 2xx.
        assert!(outcome(201, "", "example.com:443").is_none());
    }

    #[tokio::test]
    async fn a_tunnel_opens_and_the_greeting_survives() {
        // Первым говорит сервер — так ведут себя SSH, SMTP и половина баз
        // данных. Съесть его приветствие значит подвесить соединение.
        let (mut client, mut proxy) = duplex(4096);
        proxy
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\nSSH-2.0-OpenSSH")
            .await
            .expect("пишется");

        let tail = perform(&mut client, &target(), None)
            .await
            .expect("прокси согласился");
        assert_eq!(tail, b"SSH-2.0-OpenSSH");
    }

    #[tokio::test]
    async fn a_refusal_names_the_target() {
        let (mut client, mut proxy) = duplex(4096);
        proxy
            .write_all(b"HTTP/1.1 403 Forbidden\r\nVia: proxy\r\n\r\n")
            .await
            .expect("пишется");

        let err = perform(&mut client, &target(), None)
            .await
            .expect_err("прокси отказал");
        let text = err.to_string();
        assert!(text.contains("example.com:443"), "нет адреса: {text}");
        assert!(text.contains("Forbidden"), "нет причины: {text}");
    }

    #[tokio::test]
    async fn a_proxy_that_hangs_up_says_so() {
        // Запрос принят, ответа нет: так выглядит прокси, которому не
        // понравился адрес назначения, но объяснять он не стал.
        let (mut client, mut proxy) = duplex(4096);
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            let _read = proxy.read(&mut buffer).await;
            drop(proxy);
        });

        let err = perform(&mut client, &target(), None)
            .await
            .expect_err("ответа нет");
        assert!(matches!(err, HttpProxyError::Disconnected(_)));
    }

    #[tokio::test]
    async fn a_reply_split_across_packets_is_still_found() {
        // Разделитель пустой строки может прийти разрезанным пополам.
        let (mut client, mut proxy) = duplex(4096);
        tokio::spawn(async move {
            proxy.write_all(b"HTTP/1.1 200 OK\r\n").await.ok();
            proxy.write_all(b"Via: proxy\r").await.ok();
            proxy.write_all("\n\r\nданные".as_bytes()).await.ok();
        });

        let tail = perform(&mut client, &target(), None)
            .await
            .expect("прокси согласился");
        assert_eq!(String::from_utf8_lossy(&tail), "данные");
    }
}
