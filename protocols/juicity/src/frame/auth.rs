//! Опознание: то, что уходит односторонним потоком сразу после рукопожатия.
//!
//! ```text
//! +---------+---------+---------+-----------+
//! | версия  | команда |  UUID   | отпечаток |
//! +---------+---------+---------+-----------+
//! |    1    |    1    |   16    |    32     |
//! +---------+---------+---------+-----------+
//! ```
//!
//! Ответа на него нет: сервер либо продолжает разговор, либо закрывает
//! соединение с кодом отказа. Поэтому запросы можно слать, не дожидаясь.
//!
//! Отпечаток выводит не пароль и не его хеш, а сам TLS: экспорт ключевого
//! материала (RFC 5705) от уже установленного соединения. Отсюда два
//! свойства. Отпечаток разный на каждом соединении, значит подслушанный не
//! годится ни для чего. И вывести его нельзя, не проведя рукопожатия, значит
//! сервер проверяет заодно, что говорит с тем же собеседником.

use penguin_core::uuid::Uuid;

/// Версия протокола в заголовке команды.
pub const VERSION: u8 = 0x00;

/// Команда опознания.
pub const CMD_AUTHENTICATE: u8 = 0x00;

/// Длина отпечатка.
pub const TOKEN_LEN: usize = 32;

/// Длина всего запроса.
pub const LEN: usize = 1 + 1 + 16 + TOKEN_LEN;

/// Собирает запрос опознания.
pub fn request(uuid: &Uuid, token: &[u8; TOKEN_LEN]) -> [u8; LEN] {
    let mut out = [0u8; LEN];
    out[0] = VERSION;
    out[1] = CMD_AUTHENTICATE;
    out[2..18].copy_from_slice(uuid.as_bytes());
    out[18..].copy_from_slice(token);
    out
}

/// Метка для экспорта ключевого материала.
///
/// **Сырые шестнадцать байт** UUID, а не его запись строкой с дефисами. Это
/// то место, где легче всего ошибиться: обе записи выглядят одинаково
/// правдоподобно, а сервер молча не признаёт вторую. Проверено по коду и
/// клиента, и сервера эталона.
pub fn label(uuid: &Uuid) -> [u8; 16] {
    *uuid.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn uuid() -> Uuid {
        TEXT.parse().expect("разбирается")
    }

    #[test]
    fn the_request_is_the_shape_the_server_reads() {
        let token = [0x5a_u8; TOKEN_LEN];
        let request = request(&uuid(), &token);

        assert_eq!(request.len(), 50);
        assert_eq!(request[0], 0x00, "версия");
        assert_eq!(request[1], 0x00, "команда опознания");
        assert_eq!(&request[2..18], uuid().as_bytes());
        assert_eq!(&request[18..], &token);
    }

    #[test]
    fn the_uuid_goes_out_as_bytes_and_not_as_text() {
        // Запись строкой длиннее шестнадцати байт, и сервер, прочитав её,
        // получил бы чужой UUID и чужой отпечаток за ним.
        let request = request(&uuid(), &[0; TOKEN_LEN]);
        assert_eq!(request[2], 0xb8);
        assert_ne!(request[2], b'b');
    }

    #[test]
    fn the_label_is_the_raw_bytes_too() {
        // Метка экспорта — то же самое место с той же ловушкой.
        assert_eq!(label(&uuid()), *uuid().as_bytes());
        assert_eq!(label(&uuid()).len(), 16);
    }
}
