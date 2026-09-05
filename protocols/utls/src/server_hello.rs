//! Разбор `ServerHello` — ровно до того, что понадобится Reality на
//! следующем шаге: версия, выбранный шифр, эхо `SessionID`, `key_share` и
//! `supported_versions`. Сертификат и остальное рукопожатие сюда не входят —
//! это уже за пределами задачи этого крейта (см. документ `lib.rs`).
//!
//! ```text
//! TLSPlaintext
//! ├─ 0x16          тип: handshake
//! ├─ версия (2 Б)
//! ├─ длина (2 Б)
//! └─ Handshake
//!    ├─ 0x02       тип: server_hello
//!    ├─ длина (3 Б)
//!    └─ ServerHello
//!       ├─ версия (2 Б) · random (32 Б)
//!       ├─ session_id      (1 Б длины + данные, эхо клиентского)
//!       ├─ cipher_suite    (2 Б)
//!       ├─ compression     (1 Б, всегда 0 — TLS 1.3 сжатие не поддерживает)
//!       └─ extensions      (2 Б длины)
//!          ├─ 0x002b supported_versions ──► настоящая версия TLS
//!          └─ 0x0033 key_share          ──► группа сервера и его ключ
//! ```
//!
//! Байты пришли из сети, и длины в них — числа с чужой стороны: каждое
//! чтение проверяет границу, а не берёт её на веру (`AGENTS.md` §4.3).
//! Обрезанный или подделанный `ServerHello` возвращает [`UtlsError`], а не
//! паникует.

use crate::error::{UtlsError, UtlsResult};
use crate::record::{CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_SERVER_HELLO};

const EXTENSION_KEY_SHARE: u16 = 51;
const EXTENSION_SUPPORTED_VERSIONS: u16 = 43;

/// Запись `key_share` сервера: выбранная группа и его публичное значение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShare {
    /// Группа, которую выбрал сервер.
    pub group: u16,
    /// Публичное значение сервера в этой группе.
    pub data: Vec<u8>,
}

/// Разобранный `ServerHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// Поле `legacy_version` тела сообщения. В TLS 1.3 оно всегда `0x0303`
    /// (см. [`crate::record::LEGACY_VERSION`]) — настоящую версию называет
    /// [`Self::supported_version`].
    pub legacy_version: u16,
    /// Случайное значение сервера (`ServerHello.random`).
    pub random: [u8; 32],
    /// Эхо `SessionID`, которое клиент отправил в `ClientHello`. Длина может
    /// быть короче 32 байт или нулевой — сервер имеет на это право, хотя ни
    /// один настоящий TLS 1.3 сервер так не делает.
    pub session_id: Vec<u8>,
    /// Шифр, который выбрал сервер, — один из тех, что были в `ClientHello`.
    pub cipher_suite: u16,
    /// Метод сжатия. У TLS 1.3 всегда `0`.
    pub compression_method: u8,
    /// `key_share`, если сервер его прислал. `None` означает, что впереди
    /// `HelloRetryRequest` или сервер остался на TLS 1.2 — разбирать это
    /// дальше не дело этого крейта.
    pub key_share: Option<KeyShare>,
    /// Единственное значение из `supported_versions`, если оно было.
    pub supported_version: Option<u16>,
    /// Остальные расширения как есть — код и тело, без разбора внутрь. Это
    /// не лень, а честная граница: их разбор потребуется, только когда
    /// появится тот, кто ими пользуется.
    pub extensions: Vec<(u16, Vec<u8>)>,
}

/// Сколько байт нужно, чтобы разобрать одну TLS-запись с `ServerHello`.
///
/// `Ok(None)` — заголовка записи ещё не хватает; это обычное дело в потоке,
/// а не ошибка.
pub fn record_len(bytes: &[u8]) -> UtlsResult<Option<usize>> {
    let Some(header) = bytes.get(..5) else {
        return Ok(None);
    };
    if header[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(UtlsError::malformed(format!(
            "тип записи {:#04x} вместо handshake (0x16)",
            header[0]
        )));
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    Ok(Some(5 + len))
}

/// Разбирает `ServerHello` из одной полной TLS-записи (заголовок записи и
/// сообщение рукопожатия целиком — ровно столько байт, сколько назвал
/// [`record_len`]).
pub fn parse(record: &[u8]) -> UtlsResult<ServerHello> {
    let mut reader = Reader::new(record);

    let record_type = reader.u8()?;
    if record_type != CONTENT_TYPE_HANDSHAKE {
        return Err(UtlsError::malformed(format!(
            "тип записи {record_type:#04x} вместо handshake (0x16)"
        )));
    }
    reader.skip(2)?; // версия записи — не значима для ServerHello
    let record_len = reader.u16()? as usize;
    let mut handshake = Reader::new(reader.take(record_len)?);

    let message_type = handshake.u8()?;
    if message_type != HANDSHAKE_TYPE_SERVER_HELLO {
        return Err(UtlsError::malformed(format!(
            "тип сообщения {message_type:#04x} вместо server_hello (0x02)"
        )));
    }
    let message_len = handshake.u24()? as usize;
    let mut body = Reader::new(handshake.take(message_len)?);

    let legacy_version = body.u16()?;
    let random = body.array::<32>()?;

    let session_id_len = body.u8()? as usize;
    let session_id = body.take(session_id_len)?.to_vec();

    let cipher_suite = body.u16()?;
    let compression_method = body.u8()?;

    let mut key_share = None;
    let mut supported_version = None;
    let mut extensions = Vec::new();

    // extensions — необязательное поле формата: сервер, ответивший TLS 1.2
    // без единого расширения, вправе не прислать даже нулевую длину списка.
    if body.remaining() > 0 {
        let extensions_len = body.u16()? as usize;
        let mut list = Reader::new(body.take(extensions_len)?);

        while list.remaining() > 0 {
            let ext_type = list.u16()?;
            let ext_len = list.u16()? as usize;
            let ext_body = list.take(ext_len)?;

            match ext_type {
                EXTENSION_KEY_SHARE => {
                    let mut ks = Reader::new(ext_body);
                    let group = ks.u16()?;
                    let data_len = ks.u16()? as usize;
                    let data = ks.take(data_len)?.to_vec();
                    key_share = Some(KeyShare { group, data });
                }
                EXTENSION_SUPPORTED_VERSIONS => {
                    let mut sv = Reader::new(ext_body);
                    supported_version = Some(sv.u16()?);
                }
                other => extensions.push((other, ext_body.to_vec())),
            }
        }
    }

    Ok(ServerHello {
        legacy_version,
        random,
        session_id,
        cipher_suite,
        compression_method,
        key_share,
        supported_version,
        extensions,
    })
}

/// Чтение из буфера с проверкой границ на каждом шаге — байты пришли с той
/// стороны, и любое чтение без проверки читает за границей буфера по чужому
/// числу.
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

    fn take(&mut self, len: usize) -> UtlsResult<&'a [u8]> {
        let end = self.position.checked_add(len).ok_or_else(too_short)?;
        let slice = self.data.get(self.position..end).ok_or_else(too_short)?;
        self.position = end;
        Ok(slice)
    }

    fn skip(&mut self, len: usize) -> UtlsResult<()> {
        self.take(len).map(|_| ())
    }

    fn u8(&mut self) -> UtlsResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> UtlsResult<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> UtlsResult<u32> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    fn array<const N: usize>(&mut self) -> UtlsResult<[u8; N]> {
        let b = self.take(N)?;
        b.try_into().map_err(|_| too_short())
    }
}

fn too_short() -> UtlsError {
    UtlsError::malformed("не хватает байт: запись обрезана")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собирает запись с `ServerHello`, у которого есть `key_share` и
    /// `supported_versions`, — то, что реально шлёт сервер TLS 1.3.
    fn server_hello_record(cipher_suite: u16, group: u16, key_data: &[u8]) -> Vec<u8> {
        let mut key_share_ext = Vec::new();
        key_share_ext.extend_from_slice(&group.to_be_bytes());
        key_share_ext.extend_from_slice(&(key_data.len() as u16).to_be_bytes());
        key_share_ext.extend_from_slice(key_data);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&EXTENSION_SUPPORTED_VERSIONS.to_be_bytes());
        extensions.extend_from_slice(&2u16.to_be_bytes());
        extensions.extend_from_slice(&0x0304u16.to_be_bytes());
        extensions.extend_from_slice(&EXTENSION_KEY_SHARE.to_be_bytes());
        extensions.extend_from_slice(&(key_share_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&key_share_ext);
        // Неизвестное расширение — чтобы убедиться, что оно попадает в
        // «остальное» нетронутым, а не роняет разбор.
        extensions.extend_from_slice(&0x00ffu16.to_be_bytes());
        extensions.extend_from_slice(&3u16.to_be_bytes());
        extensions.extend_from_slice(&[1, 2, 3]);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
        body.extend_from_slice(&[0xCC; 32]); // random
        body.push(32);
        body.extend_from_slice(&[0xAA; 32]); // session_id, эхо клиентского
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0); // compression_method
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_SERVER_HELLO);
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn a_well_formed_server_hello_is_parsed_completely() {
        let record = server_hello_record(0x1301, 29, &[0xEE; 32]);
        let hello = parse(&record).expect("разбирается");

        assert_eq!(hello.legacy_version, 0x0303);
        assert_eq!(hello.session_id, vec![0xAA; 32]);
        assert_eq!(hello.cipher_suite, 0x1301);
        assert_eq!(hello.compression_method, 0);
        assert_eq!(hello.supported_version, Some(0x0304));
        assert_eq!(
            hello.key_share,
            Some(KeyShare {
                group: 29,
                data: vec![0xEE; 32]
            })
        );
        assert_eq!(hello.extensions, vec![(0x00ff, vec![1, 2, 3])]);
    }

    #[test]
    fn record_len_reports_the_full_record_size() {
        let record = server_hello_record(0x1301, 29, &[0xEE; 32]);
        let reported = record_len(&record)
            .expect("не сломано")
            .expect("есть заголовок");
        assert_eq!(reported, record.len());
    }

    #[test]
    fn record_len_is_none_until_the_header_arrives() {
        let record = server_hello_record(0x1301, 29, &[0xEE; 32]);
        assert_eq!(record_len(&record[..3]).expect("не сломано"), None);
        assert_eq!(record_len(&[]).expect("не сломано"), None);
    }

    #[test]
    fn a_truncated_server_hello_is_refused() {
        let record = server_hello_record(0x1301, 29, &[0xEE; 32]);
        for cut in 0..record.len() {
            // Каждая длина — ни `unwrap`, ни выход за границы: только
            // `Err` или, в редких случаях совпадения границ, `Ok` на
            // случайно валидном префиксе.
            let _ = parse(&record[..cut]);
        }
        assert!(parse(&record[..record.len() - 1]).is_err());
    }

    #[test]
    fn a_response_that_is_not_a_handshake_record_is_refused() {
        let err = parse(b"HTTP/1.1 200 OK\r\n\r\n").expect_err("это не TLS");
        assert!(err.to_string().contains("handshake"));
    }

    #[test]
    fn a_handshake_message_of_the_wrong_type_is_refused() {
        let mut record = server_hello_record(0x1301, 29, &[0xEE; 32]);
        // Пятый байт — тип сообщения рукопожатия, сразу после заголовка записи.
        record[5] = 0x01; // client_hello вместо server_hello
        let err = parse(&record).expect_err("это не ServerHello");
        assert!(err.to_string().contains("server_hello"));
    }

    #[test]
    fn an_unknown_extension_does_not_break_parsing() {
        let record = server_hello_record(0x1302, 23, &[0x01; 65]);
        let hello = parse(&record).expect("разбирается");
        assert_eq!(hello.extensions.len(), 1);
    }

    #[test]
    fn garbage_lengths_do_not_panic() {
        let mut record = server_hello_record(0x1301, 29, &[0xEE; 32]);
        for index in 0..record.len().min(200) {
            let original = record[index];
            record[index] = 0xFF;
            let _ = parse(&record);
            record[index] = original;
        }
    }
}
