//! Заголовок ответа: версия, статус, список признаков.
//!
//! ```text
//! +-----+--------+--------+----------+
//! | VER | STATUS | FEALEN | FEATURES |
//! +-----+--------+--------+----------+
//! |  1  |    1   |    2   |    VAR   |
//! +-----+--------+--------+----------+
//! ```
//!
//! Коды статуса — из `github.com/go-gost/relay`, `relay.go`, ревизия
//! `d323730` от 2026-07-24. Текст рядом с каждым — тот же смысл, что
//! `github.com/go-gost/x`, `internal/util/relay/conn.go` (`StatusText`,
//! ревизия `fe9d9c9` от 2026-09-05) выводит в свой журнал; своих сообщений
//! не выдумывалось.
//!
//! Признаки ответа этот крейт не разбирает. При успехе `CmdConnect` сервер
//! (`go-gost/x`, `handler/relay/connect.go`, `handleConnect`) отвечает
//! `Response{Version1, StatusOK}` без единого признака — смотреть там
//! действительно не на что. Байты признаков всё равно дочитываются и
//! отбрасываются тем, кто вызывает [`parse_header`] (`crate::connector`):
//! не сделать этого значило бы однажды принять начало потока приложения за
//! хвост чужого признака.

/// Успех.
pub const STATUS_OK: u8 = 0x00;
/// Сервер не разобрал запрос (например, пустой адрес назначения).
pub const STATUS_BAD_REQUEST: u8 = 0x01;
/// Сервер отверг имя и пароль.
pub const STATUS_UNAUTHORIZED: u8 = 0x02;
/// Операция запрещена политикой сервера: правило обхода или выключенный `bind`.
pub const STATUS_FORBIDDEN: u8 = 0x03;
/// На сервере истёк срок ожидания.
pub const STATUS_TIMEOUT: u8 = 0x04;
/// Служба на сервере недоступна.
pub const STATUS_SERVICE_UNAVAILABLE: u8 = 0x05;
/// Целевой узел недостижим.
pub const STATUS_HOST_UNREACHABLE: u8 = 0x06;
/// Целевая сеть недостижима.
pub const STATUS_NETWORK_UNREACHABLE: u8 = 0x07;
/// Внутренняя ошибка сервера.
pub const STATUS_INTERNAL_SERVER_ERROR: u8 = 0x08;

/// Заголовок ответа, разобранный из первых четырёх байт.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Версия протокола на стороне сервера.
    pub version: u8,
    /// Код статуса.
    pub status: u8,
    /// Сколько байт признаков идёт следом.
    pub feature_len: u16,
}

/// Разбирает заголовок ответа из уже прочитанных четырёх байт.
///
/// Чтение из сети сюда не входит: у заголовка нет самоочевидной длины
/// признаков, пока не прочитаны первые четыре байта, — поэтому сам обмен по
/// сети делает вызывающий ([`crate::connector`]), а этот файл только
/// раскладывает готовые байты по полям.
pub fn parse_header(bytes: [u8; 4]) -> Header {
    Header {
        version: bytes[0],
        status: bytes[1],
        feature_len: u16::from_be_bytes([bytes[2], bytes[3]]),
    }
}

/// Человекочитаемое описание статуса.
pub fn status_text(status: u8) -> &'static str {
    match status {
        STATUS_OK => "успех",
        STATUS_BAD_REQUEST => "сервер не разобрал запрос",
        STATUS_UNAUTHORIZED => "неверные имя и пароль",
        STATUS_FORBIDDEN => "запрещено политикой сервера",
        STATUS_TIMEOUT => "истёк срок ожидания на сервере",
        STATUS_SERVICE_UNAVAILABLE => "служба на сервере недоступна",
        STATUS_HOST_UNREACHABLE => "узел недостижим",
        STATUS_NETWORK_UNREACHABLE => "сеть недостижима",
        STATUS_INTERNAL_SERVER_ERROR => "внутренняя ошибка сервера",
        _ => "сервер отказал без объяснения",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_fields_are_read_in_order() {
        let header = parse_header([0x01, 0x00, 0x00, 0x07]);
        assert_eq!(
            header,
            Header {
                version: 0x01,
                status: 0x00,
                feature_len: 7,
            }
        );
    }

    #[test]
    fn feature_len_is_big_endian() {
        // Перепутать порядок байт — значит дочитать не ту длину и either
        // потерять начало потока приложения, либо зависнуть в ожидании
        // байт, которых сервер не пришлёт.
        let header = parse_header([0x01, 0x00, 0x01, 0x00]);
        assert_eq!(header.feature_len, 0x0100);
    }

    #[test]
    fn every_named_status_has_its_own_text() {
        let statuses = [
            STATUS_OK,
            STATUS_BAD_REQUEST,
            STATUS_UNAUTHORIZED,
            STATUS_FORBIDDEN,
            STATUS_TIMEOUT,
            STATUS_SERVICE_UNAVAILABLE,
            STATUS_HOST_UNREACHABLE,
            STATUS_NETWORK_UNREACHABLE,
            STATUS_INTERNAL_SERVER_ERROR,
        ];
        for (i, a) in statuses.iter().enumerate() {
            for b in &statuses[i + 1..] {
                assert_ne!(status_text(*a), status_text(*b), "{a} и {b}");
            }
        }
    }

    #[test]
    fn an_unknown_status_still_gets_a_readable_text() {
        assert_eq!(status_text(0xFF), "сервер отказал без объяснения");
    }
}
