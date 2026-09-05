//! `http_simple`: первый пакет выглядит запросом `GET`, ответ — страницей.
//!
//! ```text
//!  ──► GET /<первые байты шифротекста в виде %XX> HTTP/1.1\r\n
//!      Host: <host>[:port]\r\n
//!      <обычные заголовки браузера>\r\n
//!      \r\n
//!      <остаток шифротекста как есть>
//!  ◄── HTTP/1.1 200 OK\r\n...\r\n\r\n<шифротекст ответа>
//! ```
//!
//! Формат переписан из `shadowsocks/obfsplugin/http_simple.py` эталонной
//! реализации (ветка `manyuser`, `shadowsocksr-backup/shadowsocksr`) и
//! сверен со вторым, независимым источником — `src/obfs/http_simple.c` из
//! `shadowsocksr-backup/shadowsocksr-libev`. Оба сходятся в главном: путь
//! запроса — это шестнадцатеричная запись **части** шифротекста (`%XX` на
//! каждый байт), а не всего пакета; хвост, который не поместился, уходит
//! следом уже без изменений. Расходятся они только в мелочи, которая не
//! входит в договор с сервером, — сколько именно байт взять в путь (Python
//! берёт `head_size + random(0..64)`, C — `head_size + random()&0x3F`,
//! то есть `head_size + 0..63`): сервер эту границу не проверяет, он просто
//! ищет `\r\n\r\n` и берёт всё, что после. Здесь используется свой разумный
//! диапазон, а не одно из двух чисел наугад.
//!
//! # Про `head_size`
//!
//! Эталон вычисляет его эвристикой — подглядывает в ещё не зашифрованные
//! байty и по первому байту гадает, IPv4 там, IPv6 или домен (см.
//! `get_head_size` в `plain.py`). Нам гадать не нужно: адрес назначения
//! кодирует [`penguin_transport::addr::socks`] здесь же, в
//! [`crate::outbound`], и его длина известна точно. `head_size`, который сюда
//! передаётся, — это IV шифра плюс точная длина адреса, а не оценка.
//!
//! # Про ответ сервера
//!
//! Эталонный клиент читает ответ одним вызовом и, если `\r\n\r\n` не нашлось
//! сразу, отбрасывает уже полученные байты (`client_decode` в `http_simple.py`
//! возвращает `(b'', False)` без накопления буфера). Здесь это исправлено:
//! заголовки копятся, пока не встретится конец, — так надёжнее, а формату
//! протокола это не противоречит: граница всё равно ищется по тем же байтам
//! `\r\n\r\n`, только не обязательно в одном чтении.

use bytes::{Buf, BytesMut};
use rand::Rng;

use crate::error::{ShadowsocksrError, ShadowsocksrResult};

/// Конец заголовков HTTP.
const HEADER_END: &[u8] = b"\r\n\r\n";

/// Сколько байт заголовков ответа принимать, прежде чем считать, что на том
/// конце не `http_simple`. Настоящий ответ — не больше пары сотен байт.
const MAX_HEAD: usize = 16 * 1024;

/// Наборы user-agent обычных браузеров — списаны из эталона дословно: сервер
/// их не проверяет, но правдоподобный набор не выглядит подозрительно у тех,
/// кто смотрит на трафик поверхностно.
const USER_AGENTS: [&str; 12] = [
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/44.0",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0",
    "Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)",
    "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Linux; Android 4.4; Nexus 5 Build/BuildID) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
];

/// Состояние `http_simple` на одно соединение.
pub(crate) struct HttpSimpleState {
    host: String,
    port: u16,
    /// `obfs_param`: свой список хостов (через запятую) и, после `#`, свои
    /// заголовки вместо набора по умолчанию. Пусто — берём хост сервера.
    param: Option<String>,
    /// IV шифра плюс точная длина закодированного адреса назначения.
    head_size: usize,
    sent_header: bool,
    recv_buf: BytesMut,
    recv_done: bool,
}

impl HttpSimpleState {
    /// Заводит состояние. Ни одного байта при этом не уходит.
    pub(crate) fn new(host: String, port: u16, param: Option<String>, head_size: usize) -> Self {
        Self {
            host,
            port,
            param,
            head_size,
            sent_header: false,
            recv_buf: BytesMut::new(),
            recv_done: false,
        }
    }

    /// Оборачивает исходящий шифротекст. После первого вызова — тождество.
    pub(crate) fn client_encode(&mut self, buf: &[u8]) -> Vec<u8> {
        if self.sent_header {
            return buf.to_vec();
        }
        self.sent_header = true;

        let extra = rand::thread_rng().gen_range(0..64);
        let head_len = (self.head_size + extra).min(buf.len());
        let (head, rest) = buf.split_at(head_len);

        let mut out = request(head, &self.host, self.port, self.param.as_deref());
        out.extend_from_slice(rest);
        out
    }

    /// Остались ли непрочитанные до конца заголовки ответа.
    ///
    /// Нужно отличать чистый конец потока (сервер закрыл соединение, ничего
    /// не ответив) от обрыва посреди заголовков.
    pub(crate) fn has_pending_header(&self) -> bool {
        !self.recv_done && !self.recv_buf.is_empty()
    }

    /// Снимает заголовки ответа. Пока конец заголовков не встретился,
    /// копит их и возвращает пустой результат — это не ошибка, а ожидание.
    pub(crate) fn client_decode(&mut self, incoming: &mut BytesMut) -> ShadowsocksrResult<Vec<u8>> {
        if self.recv_done {
            return Ok(incoming.split().to_vec());
        }

        self.recv_buf.extend_from_slice(incoming);
        incoming.clear();

        let Some(at) = find(&self.recv_buf, HEADER_END) else {
            if self.recv_buf.len() > MAX_HEAD {
                return Err(ShadowsocksrError::malformed(
                    "ответ http_simple без конца заголовков: на том конце не эта надстройка",
                ));
            }
            return Ok(Vec::new());
        };

        self.recv_buf.advance(at + HEADER_END.len());
        self.recv_done = true;
        Ok(self.recv_buf.split().to_vec())
    }
}

/// Кодирует байты как `%XX%XX...` — так же, как `encode_head` в эталоне.
fn encode_head(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 3);
    for byte in data {
        out.push('%');
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Собирает поддельный запрос `GET`.
fn request(head: &[u8], host: &str, port: u16, param: Option<&str>) -> Vec<u8> {
    let hosts_field = param.filter(|p| !p.is_empty()).unwrap_or(host);
    let (hosts_field, body) = match hosts_field.find('#') {
        Some(at) => (
            &hosts_field[..at],
            Some(
                hosts_field[at + 1..]
                    .replace("\\n", "\n")
                    .replace('\n', "\r\n"),
            ),
        ),
        None => (hosts_field, None),
    };
    let chosen_host = hosts_field
        .split(',')
        .nth(rand::thread_rng().gen_range(0..hosts_field.split(',').count()))
        .unwrap_or(host)
        .trim();

    let authority = if port == 80 {
        chosen_host.to_owned()
    } else {
        format!("{chosen_host}:{port}")
    };

    let mut text = format!(
        "GET /{} HTTP/1.1\r\nHost: {authority}\r\n",
        encode_head(head)
    );
    match body {
        Some(body) => {
            text.push_str(&body);
            text.push_str("\r\n\r\n");
        }
        None => {
            let agent = USER_AGENTS[rand::thread_rng().gen_range(0..USER_AGENTS.len())];
            text.push_str(&format!(
                "User-Agent: {agent}\r\n\
                 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
                 Accept-Language: en-US,en;q=0.8\r\n\
                 Accept-Encoding: gzip, deflate\r\n\
                 DNT: 1\r\n\
                 Connection: keep-alive\r\n\r\n"
            ));
        }
    }
    text.into_bytes()
}

/// Где в `haystack` начинается `needle`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_write_looks_like_a_get_request() {
        // Буфер намного больше `head_size` плюс худший случай довеска
        // (0..64), чтобы хвост точно остался обычным текстом независимо от
        // того, сколько случайных байт добавилось к границе на этот раз.
        let mut buf = vec![1u8, 2, 3];
        buf.extend_from_slice(&[b'x'; 200]);
        let mut state = HttpSimpleState::new("example.com".into(), 8388, None, 3);
        let out = state.client_encode(&buf);
        let text = String::from_utf8_lossy(&out);

        assert!(text.starts_with("GET /%01%02%03"), "{text}");
        assert!(text.contains("Host: example.com:8388\r\n"), "{text}");

        // Тело до конца заголовков — это первые байты `buf` в виде `%XX`;
        // хвост после `\r\n\r\n` — оставшиеся байты как есть, без изменений.
        let head_end = out
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("есть конец заголовков")
            + 4;
        let tail = &out[head_end..];
        assert_eq!(tail, &buf[buf.len() - tail.len()..]);
    }

    #[test]
    fn the_port_is_hidden_when_it_is_eighty() {
        let mut state = HttpSimpleState::new("example.com".into(), 80, None, 0);
        let out = state.client_encode(b"x");
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("Host: example.com\r\n"), "{text}");
        assert!(!text.contains("example.com:80"), "{text}");
    }

    #[test]
    fn only_the_first_write_gets_a_header() {
        let mut state = HttpSimpleState::new("example.com".into(), 8388, None, 100);
        let _ = state.client_encode(b"first");
        let second = state.client_encode(b"second");
        assert_eq!(second, b"second");
    }

    #[test]
    fn a_custom_obfs_param_overrides_the_host() {
        let mut state = HttpSimpleState::new(
            "example.com".into(),
            8388,
            Some("cdn.example.net".into()),
            0,
        );
        let out = state.client_encode(b"x");
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("Host: cdn.example.net:8388\r\n"), "{text}");
    }

    #[test]
    fn a_hash_in_obfs_param_replaces_the_default_headers() {
        // Всё после `#` — свой текст заголовков вместо набора по умолчанию;
        // `\n` в настройках означает перевод строки HTTP (`\r\n`).
        let mut state = HttpSimpleState::new(
            "example.com".into(),
            8388,
            Some("example.com#X-Custom: 1\nX-Other: 2".into()),
            0,
        );
        let out = state.client_encode(b"x");
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("X-Custom: 1\r\nX-Other: 2\r\n\r\n"), "{text}");
        assert!(!text.contains("User-Agent"), "{text}");
    }

    #[test]
    fn the_response_headers_are_stripped() {
        let mut state = HttpSimpleState::new("example.com".into(), 8388, None, 0);
        let mut incoming =
            BytesMut::from(&b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nsecret-ciphertext"[..]);
        let out = state.client_decode(&mut incoming).expect("разбирается");
        assert_eq!(out, b"secret-ciphertext");
    }

    #[test]
    fn a_response_split_across_reads_is_assembled() {
        let mut state = HttpSimpleState::new("example.com".into(), 8388, None, 0);
        let wire = b"HTTP/1.1 200 OK\r\n\r\npayload";

        // "HTTP/1.1 200 OK\r\n\r\n" — ровно 19 байт; здесь до конца заголовков
        // не хватает одного байта, и `\r\n\r\n` ещё не встретился целиком.
        let mut first_half = BytesMut::from(&wire[..18]);
        assert!(state.client_decode(&mut first_half).unwrap().is_empty());

        let mut second_half = BytesMut::from(&wire[18..]);
        let out = state.client_decode(&mut second_half).unwrap();
        assert_eq!(out, b"payload");
    }

    #[test]
    fn bytes_after_the_header_boundary_survive_untouched() {
        // После первого разбора надстройка больше не трогает поток — это уже
        // чистый шифротекст, который снимает слой шифра выше.
        let mut state = HttpSimpleState::new("example.com".into(), 8388, None, 0);
        let mut incoming = BytesMut::from(&b"HTTP/1.1 200 OK\r\n\r\nfirst"[..]);
        let _ = state.client_decode(&mut incoming).unwrap();

        let mut more = BytesMut::from(&b"second"[..]);
        let out = state.client_decode(&mut more).unwrap();
        assert_eq!(out, b"second");
    }

    #[test]
    fn an_endless_header_is_refused() {
        // Иначе сервер, никогда не закрывающий заголовки, копил бы память
        // бесконечно.
        let mut state = HttpSimpleState::new("example.com".into(), 8388, None, 0);
        let mut noise = BytesMut::from(vec![b'x'; MAX_HEAD + 1].as_slice());
        assert!(state.client_decode(&mut noise).is_err());
    }
}
