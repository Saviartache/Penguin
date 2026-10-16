//! Заголовки записи TLS (тип, версия, длина u16) и рукопожатия (тип, длина u24).

/// Запись несёт сообщение рукопожатия.
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;

/// Версия в заголовке записи: TLS 1.0, как у настоящих клиентов (мидлбоксы).
pub const RECORD_VERSION: u16 = 0x0301;

/// `legacy_version` в теле `ClientHello`/`ServerHello`: TLS 1.2.
pub const LEGACY_VERSION: u16 = 0x0303;

/// `ClientHello` внутри сообщения рукопожатия.
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

/// `ServerHello` внутри сообщения рукопожатия.
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;

/// Оборачивает сообщение рукопожатия в одну запись TLS.
pub fn wrap_record(handshake_message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + handshake_message.len());
    out.push(CONTENT_TYPE_HANDSHAKE);
    out.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    let len = u16::try_from(handshake_message.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(handshake_message);
    out
}

/// Заголовок рукопожатия: тип и трёхбайтная длина тела.
pub fn handshake_header(message_type: u8, body_len: usize) -> [u8; 4] {
    let len = (body_len as u32).to_be_bytes();
    [message_type, len[1], len[2], len[3]]
}

/// Оборачивает тело в заголовок рукопожатия.
pub fn wrap_handshake(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&handshake_header(message_type, body.len()));
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
