//! Заголовок Host из обычного HTTP.
//!
//! Незашифрованного HTTP осталось немного, но он есть: обновления, проверки
//! связи у операционной системы, страницы-заглушки публичных сетей. Имя из
//! них достаётся заметно проще, чем из TLS, — оно лежит текстом.

/// Наибольший объём, в котором ищется заголовок.
///
/// Заголовки HTTP укладываются в килобайты; читать больше — значит копить
/// чужие данные в надежде на заголовок, которого нет.
const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Методы, с которых начинается запрос.
///
/// Проверка нужна, чтобы не принять за HTTP первые байты произвольного
/// двоичного протокола, где случайно встретилось слово `Host:`.
const METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"TRACE ",
    b"CONNECT ",
];

/// Достаёт имя хоста из заголовка `Host`.
pub fn extract_host(data: &[u8]) -> Option<&str> {
    let data = &data[..data.len().min(MAX_HEADER_BYTES)];

    if !METHODS.iter().any(|method| data.starts_with(method)) {
        return None;
    }

    // Заголовки кончаются пустой строкой. Пока её нет, запрос ещё не пришёл
    // целиком, и `Host` мог не успеть появиться.
    let head_end = find(data, b"\r\n\r\n").or_else(|| find(data, b"\n\n"))?;
    let head = &data[..head_end];

    for line in split_lines(head) {
        let Some((name, value)) = split_header(line) else {
            continue;
        };
        if !name.eq_ignore_ascii_case("host") {
            continue;
        }

        let value = value.trim();
        // В `Host` может стоять порт — он нам не нужен, имя есть имя.
        // IPv6 в квадратных скобках здесь не встречается: правила по именам
        // к числовому адресу всё равно не применяются.
        let host = value.split(':').next()?.trim();
        return Some(host).filter(|host| is_plausible_host(host));
    }
    None
}

fn split_lines(head: &[u8]) -> impl Iterator<Item = &str> {
    std::str::from_utf8(head)
        .unwrap_or_default()
        .split('\n')
        .map(|line| line.trim_end_matches('\r'))
}

fn split_header(line: &str) -> Option<(&str, &str)> {
    line.split_once(':')
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Похоже ли это на доменное имя.
fn is_plausible_host(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(host: &str) -> Vec<u8> {
        format!("GET /path HTTP/1.1\r\nUser-Agent: test\r\nHost: {host}\r\n\r\n").into_bytes()
    }

    #[test]
    fn extracts_the_host() {
        assert_eq!(extract_host(&request("example.com")), Some("example.com"));
    }

    #[test]
    fn drops_the_port() {
        assert_eq!(
            extract_host(&request("example.com:8080")),
            Some("example.com")
        );
    }

    #[test]
    fn header_name_is_case_insensitive() {
        let request = b"GET / HTTP/1.1\r\nHOST: example.com\r\n\r\n";
        assert_eq!(extract_host(request), Some("example.com"));
    }

    #[test]
    fn incomplete_request_yields_nothing() {
        // Пока пустой строки нет, `Host` мог просто не успеть прийти.
        let partial = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert_eq!(extract_host(partial), None);
    }

    #[test]
    fn non_http_yields_nothing() {
        // Первые байты TLS начинаются с 0x16 и на метод не похожи.
        assert_eq!(extract_host(&[0x16, 0x03, 0x01, 0x00, 0x50]), None);
        assert_eq!(extract_host(b""), None);
        // Слово `Host:` внутри чужого двоичного протокола не должно сойти за
        // HTTP.
        assert_eq!(extract_host(b"\x00\x01Host: example.com\r\n\r\n"), None);
    }

    #[test]
    fn request_without_host_yields_nothing() {
        assert_eq!(extract_host(b"GET / HTTP/1.0\r\n\r\n"), None);
    }

    #[test]
    fn oversized_input_is_bounded() {
        // Поток без единого перевода строки не должен заставить нас
        // просмотреть мегабайты.
        let mut flood = b"GET / HTTP/1.1\r\n".to_vec();
        flood.extend(std::iter::repeat_n(b'x', 1_000_000));
        assert_eq!(extract_host(&flood), None);
    }

    #[test]
    fn accepts_lf_only_line_endings() {
        // Так пишут самодельные клиенты, и формально это допустимо.
        assert_eq!(
            extract_host(b"GET / HTTP/1.0\nHost: example.com\n\n"),
            Some("example.com")
        );
    }
}
