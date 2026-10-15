//! Запрос XHTTP `stream-one` — без сети.
//!
//! Сверено по Xray-core `v26.3.27`, `transport/internet/splithttp`:
//! `config.go` (`GetNormalizedPath`, `GetNormalizedQuery`,
//! `FillStreamRequest`), `xpadding.go` (длина и место отступа),
//! `client.go` (`OpenStream`) и `common/utils/browser.go` (заголовки
//! `fetch` от Chrome).

use rand::Rng;

use crate::browser::{CHROME_USER_AGENT, CHROME_VERSION};
use crate::h3::Request;

/// Длина отступа: умолчание Xray (`GetNormalizedXPaddingBytes`), сервер
/// проверяет его же.
const PADDING: std::ops::RangeInclusive<usize> = 100..=1000;

/// Запрос `stream-one`: один `POST`, тело в обе стороны.
pub fn stream_one(authority: &str, path: &str) -> Request {
    let (path, query) = normalize(path);
    let target = match query {
        "" => path.clone(),
        query => format!("{path}?{query}"),
    };
    let padding = "X".repeat(rand::thread_rng().gen_range(PADDING));
    // Отступ — в `Referer`, адрес запроса с подменённой строкой запроса
    // (`ApplyXPaddingToHeader`, `PlacementQueryInHeader`).
    let referer = format!("https://{authority}{path}?x_padding={padding}");

    let request = Request::new("POST", authority, target);
    chrome_fetch_headers()
        .into_iter()
        .fold(request, |request, (name, value)| {
            request.header(name, value)
        })
        .header("referer", referer)
        .header("content-type", "application/grpc")
}

/// Путь с `/` в начале и в конце и строка запроса после `?`
/// (`GetNormalizedPath`, `GetNormalizedQuery`).
fn normalize(raw: &str) -> (String, &str) {
    let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
    let mut path = path.to_owned();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    (path, query)
}

/// Заголовки Chrome для `fetch` (`applyMasqueradedHeaders`).
fn chrome_fetch_headers() -> [(&'static str, String); 12] {
    // `getGreasedChUa(144, "chrome")`: неверный бренд по остаткам от 144,
    // порядок — тождественная перестановка (144 % 6 = 0).
    let ch_ua = format!(
        "\"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"{CHROME_VERSION}\", \
         \"Google Chrome\";v=\"{CHROME_VERSION}\""
    );
    [
        ("sec-ch-ua", ch_ua),
        ("sec-ch-ua-mobile", "?0".to_owned()),
        ("sec-ch-ua-platform", "\"Windows\"".to_owned()),
        ("dnt", "1".to_owned()),
        ("user-agent", CHROME_USER_AGENT.to_owned()),
        ("accept-language", "en-US,en;q=0.9".to_owned()),
        ("sec-fetch-mode", "cors".to_owned()),
        ("sec-fetch-dest", "empty".to_owned()),
        ("sec-fetch-site", "same-origin".to_owned()),
        ("priority", "u=1, i".to_owned()),
        ("cache-control", "no-cache".to_owned()),
        ("pragma", "no-cache".to_owned()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h3::qpack::field;

    fn fields(request: &Request) -> Vec<(String, String)> {
        field::decode(&request.encode(), usize::MAX)
            .expect("разбирается")
            .into_iter()
            .map(|f| {
                let text = |b: Vec<u8>| String::from_utf8(b).expect("текст");
                (text(f.name), text(f.value))
            })
            .collect()
    }

    fn get<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
        fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn the_path_is_normalized_like_xray() {
        assert_eq!(normalize(""), ("/".to_owned(), ""));
        assert_eq!(normalize("xhttp"), ("/xhttp/".to_owned(), ""));
        assert_eq!(normalize("/a/b?ed=2048"), ("/a/b/".to_owned(), "ed=2048"));
    }

    #[test]
    fn stream_one_is_a_post_with_padding_in_the_referer() {
        let fields = fields(&stream_one("cdn.example.com", "/up?k=v"));
        assert_eq!(get(&fields, ":method"), Some("POST"));
        assert_eq!(get(&fields, ":path"), Some("/up/?k=v"));
        assert_eq!(get(&fields, ":authority"), Some("cdn.example.com"));
        assert_eq!(get(&fields, "content-type"), Some("application/grpc"));

        let referer = get(&fields, "referer").expect("отступ");
        let padding = referer
            .strip_prefix("https://cdn.example.com/up/?x_padding=")
            .expect("строка запроса подменена отступом");
        assert!(PADDING.contains(&padding.len()));
        assert!(padding.bytes().all(|b| b == b'X'));
    }

    #[test]
    fn the_browser_headers_are_chromes() {
        let fields = fields(&stream_one("a", "/"));
        assert_eq!(
            get(&fields, "sec-ch-ua"),
            Some("\"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"144\", \"Google Chrome\";v=\"144\"")
        );
        assert_eq!(get(&fields, "sec-fetch-mode"), Some("cors"));
        assert!(get(&fields, "user-agent").is_some_and(|ua| ua.contains("Chrome/144")));
    }
}
