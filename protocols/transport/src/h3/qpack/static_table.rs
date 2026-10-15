//! Статическая таблица QPACK (RFC 9204, приложение A).
//!
//! Снята с текста RFC разбором таблицы, а не набрана по памяти; ячейки,
//! перенесённые в тексте на вторую строку, склеены. Независимая сверка —
//! таблица `PREDEFINED_HEADERS` крейта `h3` 0.0.8: совпадает построчно.

/// Чем запись таблицы подходит к полю.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// Совпали и имя, и значение — поле передаётся одним индексом.
    Full(u64),
    /// Совпало только имя — значение идёт литералом.
    Name(u64),
}

/// Ищет поле в таблице. Таблица маленькая, перебор дешевле любой карты.
pub fn find(name: &[u8], value: &[u8]) -> Option<Match> {
    let mut by_name = None;
    for (index, (entry_name, entry_value)) in (0u64..).zip(TABLE) {
        if entry_name.as_bytes() != name {
            continue;
        }
        if entry_value.as_bytes() == value {
            return Some(Match::Full(index));
        }
        by_name.get_or_insert(Match::Name(index));
    }
    by_name
}

/// Запись таблицы по индексу.
pub fn get(index: u64) -> Option<(&'static str, &'static str)> {
    usize::try_from(index)
        .ok()
        .and_then(|index| TABLE.get(index))
        .copied()
}

const TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indices_match_the_rfc() {
        // Опорные строки RFC 9204, приложение A.
        assert_eq!(get(0), Some((":authority", "")));
        assert_eq!(get(15), Some((":method", "CONNECT")));
        assert_eq!(get(25), Some((":status", "200")));
        assert_eq!(get(98), Some(("x-frame-options", "sameorigin")));
        assert_eq!(get(99), None);
    }

    #[test]
    fn a_full_match_beats_a_name_match() {
        assert_eq!(find(b":method", b"CONNECT"), Some(Match::Full(15)));
        assert_eq!(find(b":method", b"PATCH"), Some(Match::Name(15)));
        assert_eq!(find(b":protocol", b"connect-udp"), None);
    }
}
