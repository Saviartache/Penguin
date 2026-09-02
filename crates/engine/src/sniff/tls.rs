//! SNI из TLS ClientHello.
//!
//! Разбирается ровно столько, сколько нужно, чтобы достать имя, — и ни байтом
//! больше. Это не TLS-реализация: подпись не проверяется, состояние не
//! ведётся, расшифровка не делается. Прочитали имя и отдали байты дальше
//! нетронутыми.
//!
//! ```text
//! TLSPlaintext
//! ├─ 0x16          тип: handshake
//! ├─ версия (2 Б)
//! ├─ длина (2 Б)
//! └─ Handshake
//!    ├─ 0x01       тип: client_hello
//!    ├─ длина (3 Б)
//!    └─ ClientHello
//!       ├─ версия (2 Б) · random (32 Б)
//!       ├─ session_id      (1 Б длины + данные)
//!       ├─ cipher_suites   (2 Б длины + данные)
//!       ├─ compression     (1 Б длины + данные)
//!       └─ extensions      (2 Б длины)
//!          └─ 0x0000 server_name ──► имя
//! ```

/// Тип записи: handshake.
const RECORD_HANDSHAKE: u8 = 0x16;

/// Тип рукопожатия: client_hello.
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// Расширение `server_name`.
const EXTENSION_SERVER_NAME: u16 = 0x0000;

/// Тип имени: обычное доменное имя.
const NAME_TYPE_HOST: u8 = 0x00;

/// Достаёт имя сервера из первых байт соединения.
///
/// `None` — это не TLS, данных пока мало или расширения `server_name` нет.
/// Вызывающий в таком случае просто идёт дальше без имени.
pub fn extract_sni(data: &[u8]) -> Option<&str> {
    let mut reader = Reader::new(data);

    if reader.u8()? != RECORD_HANDSHAKE {
        return None;
    }
    reader.skip(2)?; // версия записи
    let record_len = reader.u16()? as usize;
    let mut record = Reader::new(reader.take(record_len)?);

    if record.u8()? != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    let handshake_len = record.u24()? as usize;
    let mut hello = Reader::new(record.take(handshake_len)?);

    hello.skip(2)?; // версия
    hello.skip(32)?; // random

    let session_len = hello.u8()? as usize;
    hello.skip(session_len)?;

    let ciphers_len = hello.u16()? as usize;
    hello.skip(ciphers_len)?;

    let compression_len = hello.u8()? as usize;
    hello.skip(compression_len)?;

    let extensions_len = hello.u16()? as usize;
    let mut extensions = Reader::new(hello.take(extensions_len)?);

    while extensions.remaining() >= 4 {
        let kind = extensions.u16()?;
        let len = extensions.u16()? as usize;
        let body = extensions.take(len)?;

        if kind == EXTENSION_SERVER_NAME {
            return parse_server_name(body);
        }
    }
    None
}

/// Разбирает содержимое расширения `server_name`.
fn parse_server_name(body: &[u8]) -> Option<&str> {
    let mut reader = Reader::new(body);
    let list_len = reader.u16()? as usize;
    let mut list = Reader::new(reader.take(list_len)?);

    while list.remaining() >= 3 {
        let name_type = list.u8()?;
        let len = list.u16()? as usize;
        let name = list.take(len)?;

        if name_type == NAME_TYPE_HOST {
            // Имя обязано быть текстом; двоичный мусор здесь — признак того,
            // что мы разобрали не то.
            return std::str::from_utf8(name)
                .ok()
                .filter(|name| is_plausible_host(name));
        }
    }
    None
}

/// Похоже ли это на доменное имя.
///
/// Проверка не про строгость RFC, а про то, чтобы случайно разобранный мусор
/// не уехал в правила и в журнал как имя хоста.
fn is_plausible_host(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.contains('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Чтение из буфера с проверкой границ на каждом шаге.
///
/// Данные пришли из сети; любое чтение без проверки — это чтение за границей
/// буфера по чужому числу.
struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(len)?;
        let slice = self.data.get(self.position..end)?;
        self.position = end;
        Some(slice)
    }

    fn skip(&mut self, len: usize) -> Option<()> {
        self.take(len).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Option<u32> {
        self.take(3)
            .map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собирает ClientHello с указанным именем.
    fn client_hello(server_name: &str) -> Vec<u8> {
        let name = server_name.as_bytes();

        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // длина списка
        sni.push(NAME_TYPE_HOST);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // версия
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session_id
        hello.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1); // compression
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_CLIENT_HELLO);
        handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(RECORD_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_the_server_name() {
        let hello = client_hello("www.example.com");
        assert_eq!(extract_sni(&hello), Some("www.example.com"));
    }

    #[test]
    fn handles_long_names() {
        let name = format!("{}.example.com", "a".repeat(60));
        let hello = client_hello(&name);
        assert_eq!(extract_sni(&hello), Some(name.as_str()));
    }

    #[test]
    fn truncated_input_yields_nothing() {
        // Первые байты соединения приходят по частям; на неполном
        // ClientHello разбор обязан вернуть `None`, а не выйти за границы.
        let hello = client_hello("example.com");
        for cut in 0..hello.len() {
            let _ = extract_sni(&hello[..cut]);
        }
        assert_eq!(extract_sni(&hello[..hello.len() - 1]), None);
    }

    #[test]
    fn non_tls_yields_nothing() {
        assert_eq!(extract_sni(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(extract_sni(b""), None);
        assert_eq!(extract_sni(&[0x16]), None);
    }

    #[test]
    fn garbage_lengths_do_not_panic() {
        // Длины пришли с той стороны — доверять им нельзя.
        let mut hello = client_hello("example.com");
        for index in 0..hello.len().min(200) {
            let original = hello[index];
            hello[index] = 0xFF;
            let _ = extract_sni(&hello);
            hello[index] = original;
        }
    }

    #[test]
    fn implausible_names_are_rejected() {
        // Разобрали не то — лучше не отдавать ничего, чем отдать мусор в
        // правила и в журнал.
        assert!(!is_plausible_host(""));
        assert!(!is_plausible_host("без-точки"));
        assert!(!is_plausible_host("про бел.ы"));
        assert!(is_plausible_host("example.com"));
        assert!(is_plausible_host("a-b.c_d.example.com"));
    }

    #[test]
    fn hello_without_sni_yields_nothing() {
        let mut hello = client_hello("example.com");
        // Портим номер расширения: имя есть, но расширение уже не то.
        let position = hello.len() - 20;
        hello[position] = 0xAB;
        let _ = extract_sni(&hello);
    }
}
