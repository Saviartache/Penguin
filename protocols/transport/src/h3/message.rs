//! Запрос и ответ HTTP/3 как набор полей (RFC 9114, §4.3).
//!
//! Своего типа, а не `http::Request`: классический `CONNECT` в HTTP/3 обязан
//! идти без `:scheme` и `:path` (§4.4), а расширенный — с `:protocol`
//! (RFC 9220). Здесь псевдозаголовки задаются явно, и запрос уходит ровно
//! таким, каким собран.

use std::fmt;

use super::error::{H3Error, H3Result};
use super::qpack::{Field, field};

/// Запрос HTTP/3.
#[derive(Clone)]
pub struct Request {
    pseudo: Vec<(&'static str, String)>,
    headers: Vec<(String, String)>,
}

impl Request {
    /// Классический `CONNECT` (§4.4): только `:method` и `:authority`.
    pub fn connect(authority: impl Into<String>) -> Self {
        Self::with_pseudo(vec![
            (":method", "CONNECT".to_owned()),
            (":authority", authority.into()),
        ])
    }

    /// Расширенный `CONNECT` (RFC 9220): `:protocol`, схема `https` и путь.
    pub fn extended_connect(
        protocol: impl Into<String>,
        authority: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self::with_pseudo(vec![
            (":method", "CONNECT".to_owned()),
            (":protocol", protocol.into()),
            (":scheme", "https".to_owned()),
            (":authority", authority.into()),
            (":path", path.into()),
        ])
    }

    /// Обычный запрос по схеме `https`.
    pub fn new(
        method: impl Into<String>,
        authority: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self::with_pseudo(vec![
            (":method", method.into()),
            (":scheme", "https".to_owned()),
            (":authority", authority.into()),
            (":path", path.into()),
        ])
    }

    fn with_pseudo(pseudo: Vec<(&'static str, String)>) -> Self {
        Self {
            pseudo,
            headers: Vec::new(),
        }
    }

    /// Добавляет заголовок. Имя приводится к строчным: в HTTP/3 заглавные
    /// буквы в имени делают сообщение неверным (§4.2).
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_ascii_lowercase(), value.into()));
        self
    }

    /// Расширенный ли это `CONNECT`: такому нужно согласие сервера.
    pub fn is_extended_connect(&self) -> bool {
        self.pseudo.iter().any(|(name, _)| *name == ":protocol")
    }

    /// Размер для предела `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114, §4.2.2).
    pub fn field_section_size(&self) -> usize {
        let pseudo = self
            .pseudo
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()));
        let headers = self
            .headers
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()));
        pseudo
            .chain(headers)
            .map(|(name, value)| field::field_size(name, value))
            .sum()
    }

    /// Блок полей QPACK.
    pub fn encode(&self) -> Vec<u8> {
        let pseudo = self
            .pseudo
            .iter()
            .map(|(name, value)| (name.as_bytes(), value.as_bytes()));
        let headers = self
            .headers
            .iter()
            .map(|(name, value)| (name.as_bytes(), value.as_bytes()));
        field::encode(pseudo.chain(headers))
    }
}

/// Значения заголовков могут нести пароль — в журнал попадают только имена.
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("Request")
            .field("pseudo", &self.pseudo)
            .field("headers", &names)
            .finish()
    }
}

/// Ответ HTTP/3.
#[derive(Debug, Clone)]
pub struct Response {
    status: u16,
    headers: Vec<Field>,
}

impl Response {
    /// Код ответа.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Первое значение заголовка, если оно есть и это текст.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|field| field.name.eq_ignore_ascii_case(name.as_bytes()))
            .and_then(|field| std::str::from_utf8(&field.value).ok())
    }

    /// Собирает ответ из разобранных полей (§4.3.2).
    pub fn from_fields(fields: Vec<Field>) -> H3Result<Self> {
        let mut status = None;
        let mut headers = Vec::with_capacity(fields.len());
        for field in fields {
            check_name(&field.name)?;
            if field.name.first() != Some(&b':') {
                headers.push(field);
                continue;
            }
            // Псевдозаголовки — только до обычных и только `:status`.
            if !headers.is_empty() {
                return Err(malformed("псевдозаголовок после обычных"));
            }
            if field.name != b":status" || status.is_some() {
                return Err(malformed("лишний псевдозаголовок в ответе"));
            }
            status = Some(parse_status(&field.value)?);
        }
        let status = status.ok_or_else(|| malformed("в ответе нет `:status`"))?;
        Ok(Self { status, headers })
    }
}

/// Имя без заглавных букв (§4.2).
fn check_name(name: &[u8]) -> H3Result<()> {
    if name.is_empty() || name.iter().any(u8::is_ascii_uppercase) {
        return Err(malformed("имя поля пустое или с заглавными буквами"));
    }
    Ok(())
}

/// Код ответа — три цифры.
fn parse_status(value: &[u8]) -> H3Result<u16> {
    if value.len() != 3 || !value.iter().all(u8::is_ascii_digit) {
        return Err(malformed("`:status` не из трёх цифр"));
    }
    let status = value
        .iter()
        .fold(0u16, |acc, digit| acc * 10 + u16::from(digit - b'0'));
    if status < 100 {
        return Err(malformed("`:status` меньше 100"));
    }
    Ok(status)
}

fn malformed(reason: &str) -> H3Error {
    H3Error::Message(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, value: &str) -> Field {
        Field {
            name: name.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        }
    }

    fn decoded(request: &Request) -> Vec<(String, String)> {
        field::decode(&request.encode(), usize::MAX)
            .expect("разбирается")
            .into_iter()
            .map(|f| {
                (
                    String::from_utf8(f.name).expect("текст"),
                    String::from_utf8(f.value).expect("текст"),
                )
            })
            .collect()
    }

    #[test]
    fn a_classic_connect_has_no_scheme_or_path() {
        // RFC 9114, §4.4 — то самое, на чём споткнулся `h3` 0.0.8.
        let fields = decoded(&Request::connect("example.com:443"));
        assert_eq!(
            fields,
            [
                (":method".to_owned(), "CONNECT".to_owned()),
                (":authority".to_owned(), "example.com:443".to_owned()),
            ]
        );
    }

    #[test]
    fn an_extended_connect_carries_the_protocol() {
        let request = Request::extended_connect("connect-udp", "proxy:443", "/masque");
        assert!(request.is_extended_connect());
        assert!(!Request::connect("a:1").is_extended_connect());
        let names: Vec<String> = decoded(&request).into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            [":method", ":protocol", ":scheme", ":authority", ":path"]
        );
    }

    #[test]
    fn header_names_go_out_lowercase() {
        let request = Request::new("POST", "hysteria", "/auth").header("Hysteria-Auth", "x");
        assert!(decoded(&request).contains(&("hysteria-auth".to_owned(), "x".to_owned())));
    }

    #[test]
    fn debug_does_not_print_header_values() {
        let request = Request::connect("a:1").header("proxy-authorization", "Basic секрет");
        let text = format!("{request:?}");
        assert!(text.contains("proxy-authorization"));
        assert!(!text.contains("секрет"));
    }

    #[test]
    fn a_response_is_parsed() {
        let response =
            Response::from_fields(vec![field(":status", "233"), field("hysteria-udp", "true")])
                .expect("ответ верен");
        assert_eq!(response.status(), 233);
        assert_eq!(response.header("Hysteria-UDP"), Some("true"));
        assert_eq!(response.header("padding"), None);
    }

    #[test]
    fn malformed_responses_are_refused() {
        let cases = [
            vec![field("server", "x")],
            vec![field(":status", "20")],
            vec![field(":status", "abc")],
            vec![field("server", "x"), field(":status", "200")],
            vec![field(":status", "200"), field(":status", "200")],
            vec![field(":status", "200"), field(":path", "/")],
            vec![field(":status", "200"), field("Server", "x")],
        ];
        for fields in cases {
            assert!(matches!(
                Response::from_fields(fields),
                Err(H3Error::Message(_))
            ));
        }
    }
}
