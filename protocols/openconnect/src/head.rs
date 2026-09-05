//! Чтение и разбор заголовка ответа HTTP/1.1: общее для входа и для `CONNECT`.
//!
//! Оба обмена — POST с XML и `CONNECT` тоннеля — читают один и тот же вид
//! ответа: строка статуса, заголовки, пустая строка. Разница только в том, что
//! идёт дальше: у POST это тело заданной длины, у `CONNECT` — сразу кадры
//! CSTP. Само чтение до пустой строки и разбор заголовков не отличаются, и
//! держать это в двух местах значило бы чинить один и тот же баг дважды.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{OpenConnectError, OpenConnectResult};

/// Наибольший заголовок ответа, который мы согласны прочитать.
///
/// Сервер, отвечающий бесконечным заголовком, иначе набивал бы нам память,
/// пока не кончится.
const MAX_HEAD: usize = 32 * 1024;

/// Разобранный ответ: строка статуса и заголовки по порядку.
///
/// Заголовки хранятся списком, а не отображением: `X-CSTP-Address` в ответе
/// на `CONNECT` может повторяться с разным смыслом (IPv4 и IPv6), и карта
/// молча оставила бы только последний.
#[derive(Debug, Clone)]
pub(crate) struct Head {
    /// Код ответа: `200` у `HTTP/1.1 200 CONNECTED`.
    pub(crate) status: u16,
    /// Заголовки в порядке, в котором их прислал сервер.
    pub(crate) headers: Vec<(String, String)>,
}

impl Head {
    /// Первое значение заголовка с таким именем, без учёта регистра.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Все значения заголовка с таким именем, по порядку.
    pub(crate) fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Читает заголовок ответа целиком и разбирает его.
///
/// Возвращает разобранный заголовок и хвост — байты, пришедшие следом за
/// пустой строкой в том же чтении. Отбрасывать их нельзя: сервер вправе
/// прислать тело или первый кадр тем же пакетом, что и заголовок.
pub(crate) async fn read<S>(io: &mut S) -> OpenConnectResult<(Head, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];

    loop {
        if let Some(end) = find_head_end(&buffer) {
            let text = std::str::from_utf8(&buffer[..end])
                .map_err(|_| OpenConnectError::malformed("заголовок ответа не UTF-8"))?;
            let head = parse(text)?;
            return Ok((head, buffer[end + 4..].to_vec()));
        }
        if buffer.len() > MAX_HEAD {
            return Err(OpenConnectError::malformed(
                "заголовок ответа длиннее тридцати двух килобайт",
            ));
        }

        let read = io.read(&mut chunk).await?;
        if read == 0 {
            return Err(OpenConnectError::disconnected(
                "соединение закрылось при чтении заголовка ответа",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Где кончается заголовок: позиция перед `\r\n\r\n`.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Разбирает строку статуса и заголовки. `text` — всё до пустой строки, без
/// неё самой.
fn parse(text: &str) -> OpenConnectResult<Head> {
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| OpenConnectError::malformed("пустой ответ"))?;

    // `HTTP/1.1 200 CONNECTED` — статус лежит вторым словом; текст пояснения
    // (`CONNECTED`, `OK`, `Unauthorized`) на разбор кода не влияет.
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| {
            OpenConnectError::malformed(format!("строка статуса не разбирается: `{status_line}`"))
        })?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    Ok(Head { status, headers })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_connect_success_line_is_understood() {
        let mut io =
            std::io::Cursor::new(b"HTTP/1.1 200 CONNECTED\r\nX-CSTP-Version: 1\r\n\r\n".to_vec());
        let (head, tail) = read(&mut io).await.expect("разбирается");
        assert_eq!(head.status, 200);
        assert_eq!(head.header("x-cstp-version"), Some("1"));
        assert!(tail.is_empty());
    }

    #[test]
    fn repeated_headers_are_all_kept() {
        // У ответа на `CONNECT` `X-CSTP-Address` встречается дважды: IPv4 и
        // IPv6 под одним именем заголовка (`cstp.c`).
        let head = parse(
            "HTTP/1.1 200 CONNECTED\r\nX-CSTP-Address: 10.0.0.2\r\nX-CSTP-Address: 2001:db8::2",
        )
        .expect("разбирается");
        let addresses: Vec<&str> = head.headers_named("X-CSTP-Address").collect();
        assert_eq!(addresses, vec!["10.0.0.2", "2001:db8::2"]);
    }

    #[test]
    fn header_lookup_ignores_case() {
        let head = parse("HTTP/1.1 200 CONNECTED\r\nx-cstp-mtu: 1400").expect("разбирается");
        assert_eq!(head.header("X-CSTP-MTU"), Some("1400"));
    }

    #[test]
    fn an_auth_rejection_is_still_a_valid_head_even_with_no_body() {
        // `ocserv` шлёт `401` с пустым телом (`worker-auth.c`); заголовок
        // разбирается как обычно, а решение по коду принимает вызывающий.
        let head = parse("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0").expect("разбирается");
        assert_eq!(head.status, 401);
    }

    #[tokio::test]
    async fn data_arriving_with_the_head_is_kept_as_the_tail() {
        let mut io = std::io::Cursor::new(b"HTTP/1.1 200 CONNECTED\r\n\r\nSTF\x01".to_vec());
        let (_, tail) = read(&mut io).await.expect("разбирается");
        assert_eq!(tail, b"STF\x01");
    }

    #[tokio::test]
    async fn a_connection_closed_mid_head_is_a_disconnect_not_a_malformed_response() {
        let mut io = std::io::Cursor::new(b"HTTP/1.1 200".to_vec());
        let err = read(&mut io).await.expect_err("оборвалось");
        assert!(matches!(err, OpenConnectError::Disconnected(_)), "{err}");
    }

    #[test]
    fn a_status_line_without_a_code_is_malformed() {
        assert!(parse("не HTTP вовсе").is_err());
    }
}
