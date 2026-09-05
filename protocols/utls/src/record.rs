//! Обёртка записи TLS и заголовка рукопожатия — то немногое, что нужно знать
//! про формат TLS, не будучи ни `rustls`, ни `crypto/tls`.
//!
//! ```text
//!  запись:
//! +------+---------+--------+---------------------+
//! | тип  | версия  | длина  |     сообщение        |
//! +------+---------+--------+---------------------+
//! |  1   |    2    |   2    |       length         |
//! +------+---------+--------+---------------------+
//!
//!  сообщение рукопожатия внутри записи:
//! +------+------------+---------------------+
//! | тип  |   длина    |        тело          |
//! +------+------------+---------------------+
//! |  1   |     3      |       length         |
//! +------+------------+---------------------+
//! ```
//!
//! Версия в заголовке записи — не версия TLS, которой ведётся рукопожатие: то
//! отдельное расширение (`supported_versions`). Здесь она держится равной
//! TLS 1.0 (`0x0301`), потому что так делает каждый настоящий клиент: часть
//! оборудования на пути рвёт соединение, увидев в заголовке записи что-то
//! новее, и это тот самый мидлбокс-баг, ради которого поле осталось лгать.

/// Запись несёт сообщение рукопожатия.
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;

/// Версия в заголовке самой первой записи. См. документ модуля.
pub const RECORD_VERSION: u16 = 0x0301;

/// `legacy_version` внутри тела `ClientHello`/`ServerHello`.
///
/// В TLS 1.3 это поле уже ничего не значит — версию называет расширение
/// `supported_versions`, — но обязано остаться равным TLS 1.2, иначе сервер,
/// не понявший 1.3, откажется разбирать сообщение дальше. Заменять его на
/// реальную версию, которой хочет говорить клиент, — устаревшая по духу TLS
/// 1.2 конвенция, но именно её ждут все.
pub const LEGACY_VERSION: u16 = 0x0303;

/// `ClientHello` внутри сообщения рукопожатия.
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

/// `ServerHello` внутри сообщения рукопожатия.
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;

/// Оборачивает готовое сообщение рукопожатия в заголовок TLS-записи.
///
/// Один вызов — одна запись. Настоящие браузеры иногда режут большой
/// `ClientHello` (с шифрованным SNI не по GREASE) на несколько записей ради
/// того же мидлбокс-обхода, но у наших отпечатков сообщение всегда меньше
/// одной записи, и резать нечего.
pub fn wrap_record(handshake_message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + handshake_message.len());
    out.push(CONTENT_TYPE_HANDSHAKE);
    out.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    // Записи TLS ограничены `2^14` байт данных; отпечатки браузеров в это
    // ограничение укладываются с большим запасом, поэтому паники здесь не
    // будет, но проверка есть — на случай, если однажды кто-то соберёт
    // `ClientHello` с полем `Ticket` длиной в несколько килобайт.
    let len = u16::try_from(handshake_message.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(handshake_message);
    out
}

/// Оборачивает тело сообщения (`ClientHello` или `ServerHello`) в заголовок
/// рукопожатия: тип и трёхбайтную длину.
pub fn wrap_handshake(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(message_type);
    let len = body.len() as u32;
    out.extend_from_slice(&len.to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_starts_with_handshake_type_and_legacy_version() {
        let record = wrap_record(&[1, 2, 3]);
        assert_eq!(record[0], CONTENT_TYPE_HANDSHAKE);
        assert_eq!(&record[1..3], &RECORD_VERSION.to_be_bytes());
        assert_eq!(&record[3..5], &3u16.to_be_bytes());
        assert_eq!(&record[5..], &[1, 2, 3]);
    }

    #[test]
    fn a_handshake_header_carries_a_three_byte_length() {
        let body = vec![0xAB; 300];
        let message = wrap_handshake(HANDSHAKE_TYPE_CLIENT_HELLO, &body);
        assert_eq!(message[0], HANDSHAKE_TYPE_CLIENT_HELLO);
        assert_eq!(
            u32::from_be_bytes([0, message[1], message[2], message[3]]),
            300
        );
        assert_eq!(&message[4..], &body[..]);
    }
}
