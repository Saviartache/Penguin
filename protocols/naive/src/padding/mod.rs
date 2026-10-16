//! Дополнение трафика — сверено с эталоном (`klzgrad/naiveproxy`, тег
//! `v150.0.7871.63-1`, файлы под `src/net/tools/naive/`).
//!
//! Два механизма: заголовки согласования (этот модуль, один раз в `CONNECT` и
//! ответе) и обрамление байтового потока ([`frame`], первые 8 чтений и записей).
//!
//! Клиент шлёт `padding` всегда и `padding-type-request` с единственным
//! [`PaddingType::Variant1`]. Сервер отвечает `padding-type-reply`; без него
//! наличие `padding` в ответе означает `Variant1`, иначе дополнения нет
//! (`http_proxy_server_socket.cc`, `ParsePaddingHeaders`). Для HTTP/2 и HTTP/3
//! путь один (`OnBeforeTunnelRequest`/`OnTunnelHeadersReceived`).
//!
//! Упрощено: значение `padding` — случайный ASCII, а не коды HPACK
//! (`padding_utils.cc`, `FillNonindexHeaderValue`); `fastopen` и поддельный
//! `DATA` перед `RST_STREAM` (`spdy_session.cc`) не реализованы.

pub mod frame;

use http::HeaderMap;
use penguin_proto::random;
use penguin_transport::h3::Response;

pub use frame::PaddedStream;

/// Заголовок о поддержке дополнения; важно лишь наличие (`ParsePaddingHeaders`).
pub const HEADER_PADDING: &str = "padding";

/// Заголовок запроса: поддерживаемые типы через запятую.
pub const HEADER_TYPE_REQUEST: &str = "padding-type-request";

/// Заголовок ответа: выбранный сервером тип, одним числом.
pub const HEADER_TYPE_REPLY: &str = "padding-type-reply";

/// Какое дополнение действует на соединении.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingType {
    /// Дополнения нет: сервер не поддерживает схему или отказался от неё.
    None,
    /// Единственная схема, которую понимает эталон — и этот клиент.
    Variant1,
}

impl PaddingType {
    /// Число, которым тип записывается в заголовках (`naive_protocol.h`).
    const fn wire(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Variant1 => 1,
        }
    }

    fn from_wire(value: &str) -> Option<Self> {
        match value.trim() {
            "0" => Some(Self::None),
            "1" => Some(Self::Variant1),
            _ => None,
        }
    }
}

/// Наименьшая длина значения заголовка `padding` в запросе.
const REQUEST_PADDING_MIN: usize = 16;
/// Наибольшая длина значения заголовка `padding` в запросе.
const REQUEST_PADDING_MAX: usize = 32;

/// Символы для значения заголовка `padding`.
const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Заголовки запроса `CONNECT`, объявляющие дополнение, парами «имя, значение».
pub fn request_headers() -> [(&'static str, String); 2] {
    let len = random::range(REQUEST_PADDING_MIN as u64..REQUEST_PADDING_MAX as u64 + 1);
    let padding: String = (0..len)
        .map(|_| char::from(ALPHABET[random::range(0..ALPHABET.len() as u64) as usize]))
        .collect();

    [
        (HEADER_PADDING, padding),
        (
            HEADER_TYPE_REQUEST,
            PaddingType::Variant1.wire().to_string(),
        ),
    ]
}

/// Тип дополнения по ответу: `reply` — `padding-type-reply`, `has_padding` — есть ли `padding`.
pub fn negotiate(reply: Option<&str>, has_padding: bool) -> PaddingType {
    if let Some(reply) = reply {
        // Не разбирается: безопаснее не дополнять, чем разойтись в формате.
        return PaddingType::from_wire(reply).unwrap_or(PaddingType::None);
    }
    if has_padding {
        return PaddingType::Variant1;
    }
    PaddingType::None
}

/// [`negotiate`] по заголовкам ответа HTTP/2.
pub fn negotiate_h2(headers: &HeaderMap) -> PaddingType {
    let reply = headers
        .get(HEADER_TYPE_REPLY)
        .map(|value| value.to_str().unwrap_or_default());
    negotiate(reply, headers.contains_key(HEADER_PADDING))
}

/// [`negotiate`] по ответу HTTP/3.
pub fn negotiate_h3(response: &Response) -> PaddingType {
    negotiate(
        response.header(HEADER_TYPE_REPLY),
        response.header(HEADER_PADDING).is_some(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_padding_is_within_bounds() {
        for _ in 0..50 {
            let headers = request_headers();
            let padding = &headers[0].1;
            assert!((REQUEST_PADDING_MIN..=REQUEST_PADDING_MAX).contains(&padding.len()));
            assert!(padding.bytes().all(|b| ALPHABET.contains(&b)));
            assert_eq!(headers[1].1, "1");
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                http::HeaderName::from_bytes(name.as_bytes()).expect("имя"),
                value.parse().expect("значение"),
            );
        }
        map
    }

    #[test]
    fn an_explicit_reply_wins() {
        assert_eq!(
            negotiate_h2(&headers(&[(HEADER_TYPE_REPLY, "1")])),
            PaddingType::Variant1
        );
        assert_eq!(
            negotiate_h2(&headers(&[(HEADER_TYPE_REPLY, "0")])),
            PaddingType::None
        );
    }

    #[test]
    fn without_a_reply_the_bare_header_means_variant1() {
        assert_eq!(
            negotiate_h2(&headers(&[(HEADER_PADDING, "xxxxxxxxxxxxxxxx")])),
            PaddingType::Variant1
        );
    }

    #[test]
    fn no_headers_at_all_means_no_padding() {
        assert_eq!(negotiate_h2(&headers(&[])), PaddingType::None);
    }

    #[test]
    fn http3_answers_the_same_way() {
        use penguin_transport::h3::qpack::Field;

        let response = |pairs: &[(&str, &str)]| {
            let mut fields = vec![Field {
                name: b":status".to_vec(),
                value: b"200".to_vec(),
            }];
            fields.extend(pairs.iter().map(|(name, value)| Field {
                name: name.as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            }));
            Response::from_fields(fields).expect("ответ верен")
        };
        assert_eq!(
            negotiate_h3(&response(&[(HEADER_TYPE_REPLY, "1")])),
            PaddingType::Variant1
        );
        assert_eq!(
            negotiate_h3(&response(&[(HEADER_PADDING, "x")])),
            PaddingType::Variant1
        );
        assert_eq!(negotiate_h3(&response(&[])), PaddingType::None);
    }

    #[test]
    fn an_unreadable_reply_is_treated_as_no_padding() {
        assert_eq!(
            negotiate_h2(&headers(&[(HEADER_TYPE_REPLY, "7")])),
            PaddingType::None
        );
    }
}
