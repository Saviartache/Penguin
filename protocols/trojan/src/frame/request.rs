//! Заголовок запроса: отпечаток пароля, команда, адрес назначения.
//!
//! ```text
//! +-------------------------+------+----------------+------+----------+
//! |  hex(SHA-224(пароль))   | CRLF |     запрос     | CRLF |  данные  |
//! +-------------------------+------+----------------+------+----------+
//! |           56            |  2   |    сколько     |  2   | сколько  |
//! +-------------------------+------+----------------+------+----------+
//!
//!  запрос:  +-----+------+----------+----------+
//!           | CMD | ATYP | DST.ADDR | DST.PORT |
//!           +-----+------+----------+----------+
//!           |  1  |  1   | сколько  |    2     |
//!           +-----+------+----------+----------+
//! ```
//!
//! Адрес записан ровно так же, как в SOCKS5, и берётся из общего места
//! ([`penguin_transport::addr::socks`]): те же номера типов, тот же порядок.
//!
//! # Ответа нет
//!
//! Сервер не отвечает ничего. Не «отвечает нулём» — не отвечает вовсе: сразу
//! за заголовком в обе стороны идут данные приложения. Отсюда два следствия,
//! которые определяют весь остальной крейт.
//!
//! **Неверный пароль неотличим от верного.** Сервер, не узнавший отпечаток,
//! пересылает наши байты настоящему сайту, за который себя выдаёт, — и с
//! точки зрения клиента всё выглядит установленным. В этом весь замысел
//! протокола, и обойти его со стороны клиента нельзя.
//!
//! **Успех соединения с адресом назначения тоже неизвестен.** Недостижимый
//! адрес выглядит так же, как неверный пароль: поток открылся и молчит.

use penguin_core::address::SocketAddress;
use penguin_transport::addr::socks;
use sha2::{Digest, Sha224};

use crate::error::TrojanResult;

/// Длина отпечатка пароля на проводе: 28 байт SHA-224 в шестнадцатеричной
/// записи.
pub const HASH_LEN: usize = 56;

/// Разделитель, которым протокол отбивает части заголовка.
pub const CRLF: [u8; 2] = [0x0D, 0x0A];

/// Открыть поток до адреса назначения.
pub const CMD_CONNECT: u8 = 0x01;

/// Дальше по этому потоку пойдут датаграммы.
pub const CMD_UDP: u8 = 0x03;

/// Отпечаток пароля в том виде, в каком он уходит по сети.
///
/// Шестнадцатеричная запись строчными буквами: сервер сравнивает её побайтно,
/// и заглавные не сойдутся.
pub fn password_hash(password: &str) -> [u8; HASH_LEN] {
    let digest = Sha224::digest(password.as_bytes());

    let mut out = [0u8; HASH_LEN];
    for (pair, byte) in out.as_chunks_mut::<2>().0.iter_mut().zip(digest) {
        pair[0] = hex_digit(byte >> 4);
        pair[1] = hex_digit(byte & 0x0F);
    }
    out
}

/// Шестнадцатеричная цифра строчными.
fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }
}

/// Собирает заголовок целиком.
///
/// Данные приложения дописываются следом тем, кто их пишет; отдельного вызова
/// на них нет намеренно — заголовок и первые байты стоит отправить одной
/// записью, иначе сервер увидит два пакета там, где обычный сайт шлёт один.
pub fn header(
    password: &[u8; HASH_LEN],
    command: u8,
    target: &SocketAddress,
) -> TrojanResult<Vec<u8>> {
    // С запасом на самый длинный адрес: тип, длина, 255 байт имени и порт.
    let mut out = Vec::with_capacity(HASH_LEN + 2 + 1 + 259 + 2);
    out.extend_from_slice(password);
    out.extend_from_slice(&CRLF);
    out.push(command);
    socks::encode(target, &mut out)?;
    out.extend_from_slice(&CRLF);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Отпечаток пустого пароля — известное значение SHA-224.
    ///
    /// Проверяется о чужой ответ, а не круговым прогоном: своя реализация
    /// согласится сама с собой при любой ошибке в порядке полубайт.
    const EMPTY_SHA224: &str = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";

    #[test]
    fn the_hash_matches_the_known_answer() {
        assert_eq!(password_hash("").as_slice(), EMPTY_SHA224.as_bytes());
    }

    #[test]
    fn the_hash_is_lowercase_hex_of_fixed_length() {
        // Сервер сравнивает запись побайтно: заглавные не сойдутся, и
        // выглядеть это будет как неверный пароль.
        let hash = password_hash("пароль от сервера");
        assert_eq!(hash.len(), HASH_LEN);
        assert!(
            hash.iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
            "в отпечатке не шестнадцатеричная запись строчными"
        );
    }

    #[test]
    fn different_passwords_give_different_hashes() {
        assert_ne!(password_hash("один"), password_hash("два"));
    }

    #[test]
    fn the_header_is_laid_out_the_way_the_server_reads_it() {
        let password = password_hash("secret");
        let bytes = header(&password, CMD_CONNECT, &SocketAddress::domain("a.io", 443))
            .expect("собирается");

        assert_eq!(&bytes[..HASH_LEN], password.as_slice());
        assert_eq!(&bytes[HASH_LEN..HASH_LEN + 2], &CRLF);
        assert_eq!(bytes[HASH_LEN + 2], CMD_CONNECT);
        // Дальше — адрес в записи SOCKS5: тип `3` у домена, длина, имя, порт.
        assert_eq!(
            &bytes[HASH_LEN + 3..],
            &[0x03, 4, b'a', b'.', b'i', b'o', 0x01, 0xBB, 0x0D, 0x0A]
        );
    }

    #[test]
    fn the_udp_header_differs_only_in_the_command() {
        let password = password_hash("secret");
        let target = SocketAddress::domain("a.io", 443);
        let tcp = header(&password, CMD_CONNECT, &target).expect("собирается");
        let udp = header(&password, CMD_UDP, &target).expect("собирается");

        assert_eq!(tcp.len(), udp.len());
        assert_eq!(udp[HASH_LEN + 2], CMD_UDP);
        assert_eq!(&tcp[HASH_LEN + 3..], &udp[HASH_LEN + 3..]);
    }

    #[test]
    fn a_domain_too_long_to_fit_is_refused() {
        let password = password_hash("secret");
        let long = "a".repeat(256);
        assert!(header(&password, CMD_CONNECT, &SocketAddress::domain(&long, 443)).is_err());
    }
}
