//! Заголовок запроса и ответа.
//!
//! ```text
//!  запрос:
//! +-------+------+--------+---------+-----+------+------+---------+
//! | верс. | UUID | длина  | дополн. | ком.| порт | тип  |  адрес  |
//! +-------+------+--------+---------+-----+------+------+---------+
//! |   1   |  16  |   1    | сколько |  1  |  2   |  1   | сколько |
//! +-------+------+--------+---------+-----+------+------+---------+
//!
//!  ответ:
//! +-------+--------+---------+
//! | верс. | длина  | дополн. |
//! +-------+--------+---------+
//! |   1   |   1    | сколько |
//! +-------+--------+---------+
//! ```
//!
//! # Две ловушки в записи адреса
//!
//! **Порт стоит перед типом**, а не после адреса, как в SOCKS5. **Домен — это
//! `2`**, а не `3`; тройка здесь означает IPv6, то есть ровно тот номер, под
//! которым в SOCKS5 идёт домен. Поэтому адрес пишется отдельным кодировщиком
//! ([`penguin_transport::addr::v2ray`]), а не общим с флагом: общий однажды
//! записал бы имя как IPv6, и сервер прочитал бы шестнадцать байт имени как
//! адрес.
//!
//! # Ответ приходит не сразу
//!
//! Сервер шлёт свой заголовок вместе с первыми данными, а не в ответ на наш.
//! Значит, прочитать его заранее нельзя — соединение просто зависнет. Снимает
//! его [`crate::stream`] при первом чтении.
//!
//! # Дополнения
//!
//! `xtls-rprx-vision` ([`crate::vision`]) — единственное значение `flow`,
//! которое эта реализация умеет держать; кодирует его [`crate::frame::addons`]
//! протобуф-сообщением `Addons`, как того ждёт `Xray-core`
//! (`proxy/vless/encoding/addons.proto`). Без него пишем ноль, читаем
//! сколько сказано и пропускаем — этого от заголовка ответа достаточно, его
//! содержимое нам не нужно.

use penguin_core::address::SocketAddress;
use penguin_core::uuid::Uuid;
use penguin_transport::addr::v2ray;

use crate::error::{VlessError, VlessResult};
use crate::frame::addons;

/// Версия протокола. Другой не было ни разу.
pub const VERSION: u8 = 0x00;

/// Открыть поток до адреса назначения.
pub const CMD_TCP: u8 = 0x01;

/// Дальше по этому потоку пойдут датаграммы для одного адреса.
pub const CMD_UDP: u8 = 0x02;

/// Собирает заголовок запроса. `flow` — обычно `None`; единственное другое
/// значение, которое здесь понимают, — [`addons::FLOW_VISION`]
/// (`crate::config::VlessConfig::validate` не пускает дальше ничего
/// другого).
pub fn request(
    uuid: &Uuid,
    command: u8,
    target: &SocketAddress,
    flow: Option<&str>,
) -> VlessResult<Vec<u8>> {
    // С запасом на самый длинный адрес: порт, тип, длина и 255 байт имени.
    let mut out = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + 256);
    out.push(VERSION);
    out.extend_from_slice(uuid.as_bytes());
    addons::encode(flow, &mut out);
    out.push(command);
    v2ray::encode(target, &mut out)?;
    Ok(out)
}

/// Сколько байт занимает заголовок ответа, если он пришёл целиком.
///
/// `Ok(None)` — байт пока не хватает; это не ошибка, а обычное дело в потоке.
pub fn response_len(bytes: &[u8]) -> VlessResult<Option<usize>> {
    let Some(head) = bytes.first_chunk::<2>() else {
        return Ok(None);
    };

    // Версия в ответе обязана совпасть с нашей. Не совпала — значит, на том
    // конце не VLESS: чаще всего это обычный сайт, отвечающий на наш запрос
    // страницей.
    if head[0] != VERSION {
        return Err(VlessError::malformed(format!(
            "версия ответа {:#04x} вместо {VERSION:#04x}",
            head[0]
        )));
    }

    let addons = usize::from(head[1]);
    if bytes.len() < 2 + addons {
        return Ok(None);
    }
    Ok(Some(2 + addons))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn uuid() -> Uuid {
        TEXT.parse().expect("разбирается")
    }

    #[test]
    fn the_request_is_laid_out_the_way_the_server_reads_it() {
        let bytes = request(&uuid(), CMD_TCP, &SocketAddress::domain("a.io", 443), None)
            .expect("собирается");

        assert_eq!(bytes[0], VERSION);
        assert_eq!(&bytes[1..17], uuid().as_bytes());
        assert_eq!(bytes[17], 0, "длина дополнений");
        assert_eq!(bytes[18], CMD_TCP);
        // Дальше — порт, потом тип, потом адрес. Не наоборот.
        assert_eq!(&bytes[19..], &[0x01, 0xBB, 0x02, 4, b'a', b'.', b'i', b'o']);
    }

    #[test]
    fn the_udp_request_differs_only_in_the_command() {
        let target = SocketAddress::domain("a.io", 443);
        let tcp = request(&uuid(), CMD_TCP, &target, None).expect("собирается");
        let udp = request(&uuid(), CMD_UDP, &target, None).expect("собирается");

        assert_eq!(tcp.len(), udp.len());
        assert_eq!(udp[18], CMD_UDP);
        assert_eq!(&tcp[19..], &udp[19..]);
    }

    #[test]
    fn a_domain_is_type_two_not_three() {
        // Тройка здесь означает IPv6. Перепутать их — значит отправить имя
        // туда, где сервер прочитает шестнадцать байт адреса.
        let bytes = request(
            &uuid(),
            CMD_TCP,
            &SocketAddress::domain("example.com", 443),
            None,
        )
        .expect("собирается");
        assert_eq!(bytes[21], 0x02, "домен записан не тем типом");

        let ipv6 = request(
            &uuid(),
            CMD_TCP,
            &SocketAddress::ip("2001:db8::1".parse().expect("адрес"), 443),
            None,
        )
        .expect("собирается");
        assert_eq!(ipv6[21], 0x03);
    }

    #[test]
    fn a_domain_too_long_to_fit_is_refused() {
        let long = "a".repeat(256);
        assert!(request(&uuid(), CMD_TCP, &SocketAddress::domain(&long, 443), None).is_err());
    }

    #[test]
    fn profiles_without_flow_are_byte_for_byte_unchanged() {
        // Жёсткое требование задачи: профиль без `flow` не должен ни на байт
        // отличаться от того, что уходило на провод до Vision.
        let target = SocketAddress::domain("a.io", 443);
        let bytes = request(&uuid(), CMD_TCP, &target, None).expect("собирается");
        assert_eq!(bytes[17], 0, "длина дополнений всё ещё ноль");
        assert_eq!(bytes.len(), 1 + 16 + 1 + 1 + 2 + 1 + 1 + 4);
    }

    #[test]
    fn a_vision_flow_carries_the_addons_protobuf_message() {
        let target = SocketAddress::domain("a.io", 443);
        let bytes =
            request(&uuid(), CMD_TCP, &target, Some(addons::FLOW_VISION)).expect("собирается");

        // Заголовок сдвигается ровно на длину сегмента `Addons`: один байт
        // длины плюс протобуф-сообщение (см. `frame::addons`).
        let addons_len = bytes[17] as usize;
        assert_eq!(addons_len, 18);
        let mut expected_message = vec![0x0a, 0x10];
        expected_message.extend_from_slice(addons::FLOW_VISION.as_bytes());
        assert_eq!(&bytes[18..18 + addons_len], expected_message.as_slice());
        assert_eq!(
            bytes[18 + addons_len],
            CMD_TCP,
            "команда сдвинулась вслед за Addons"
        );
    }

    #[test]
    fn a_response_without_addons_is_two_bytes() {
        assert_eq!(response_len(&[0x00, 0x00]).expect("не сломано"), Some(2));
    }

    #[test]
    fn a_response_with_addons_counts_them() {
        assert_eq!(
            response_len(&[0x00, 0x03, 1, 2, 3, b'x']).expect("не сломано"),
            Some(5)
        );
    }

    #[test]
    fn a_half_read_response_is_not_an_error() {
        // Заголовок приходит вместе с первыми данными и может быть разрезан.
        assert_eq!(response_len(&[]).expect("не сломано"), None);
        assert_eq!(response_len(&[0x00]).expect("не сломано"), None);
        assert_eq!(response_len(&[0x00, 0x03, 1, 2]).expect("не сломано"), None);
    }

    #[test]
    fn a_wrong_version_says_it_is_not_vless() {
        // Обычный сайт, ответивший страницей, начинается с `H` от `HTTP`.
        let err = response_len(b"HT").expect_err("это не VLESS");
        assert!(err.to_string().contains("версия ответа"), "{err}");
    }
}
