//! Сообщения `sock_diag` (`linux/inet_diag.h`) без обращений к ОС; раскладка — договор ядра.

use std::net::{Ipv4Addr, SocketAddrV4};

/// Перечислить сокеты семейства.
pub(super) const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// Закрыть сокет сбросом.
pub(super) const SOCK_DESTROY: u16 = 21;

/// Это запрос.
pub(super) const NLM_F_REQUEST: u16 = 0x001;
/// Подтвердить исполнение.
pub(super) const NLM_F_ACK: u16 = 0x004;
/// Перечислить всё (`NLM_F_ROOT | NLM_F_MATCH`).
pub(super) const NLM_F_DUMP: u16 = 0x300;

/// Конец перечисления.
pub(super) const NLMSG_DONE: u16 = 3;
/// Ошибка или, с кодом 0, подтверждение.
pub(super) const NLMSG_ERROR: u16 = 2;

/// `TCP_ESTABLISHED` и `TCP_SYN_SENT`: живые соединения и те, что вот-вот станут ими.
pub(super) const LIVE_STATES: u32 = 1 << 1 | 1 << 2;

/// Длина заголовка netlink.
pub(super) const HEADER_LEN: usize = 16;
/// Опознание сокета (`inet_diag_sockid`): порты, адреса, интерфейс, cookie.
pub(super) const ID_LEN: usize = 48;
/// `inet_diag_req_v2`: семейство, протокол, расширения, состояния и опознание.
const REQUEST_LEN: usize = 8 + ID_LEN;
/// Где в `inet_diag_msg` лежит опознание.
const MESSAGE_ID_OFFSET: usize = 4;
/// `AF_INET` и `IPPROTO_TCP` в Linux.
const AF_INET: u8 = 2;
const IPPROTO_TCP: u8 = 6;

/// Опознание сокета как его вернуло ядро.
pub(super) type SocketId = [u8; ID_LEN];

/// Запрос `sock_diag` для TCP поверх IPv4.
pub(super) fn request(kind: u16, flags: u16, states: u32, id: &SocketId) -> Vec<u8> {
    let length = u32::try_from(HEADER_LEN + REQUEST_LEN).unwrap_or(u32::MAX);
    let mut message = Vec::with_capacity(HEADER_LEN + REQUEST_LEN);
    message.extend_from_slice(&length.to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
    message.extend_from_slice(&[0; 8]); // Номер и порт проставит ядро.
    message.extend_from_slice(&[AF_INET, IPPROTO_TCP, 0, 0]);
    message.extend_from_slice(&states.to_ne_bytes());
    message.extend_from_slice(id);
    message
}

/// Что лежит в одном сообщении ответа.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Reply {
    /// Сокет из перечисления.
    Socket(SocketId),
    /// Перечисление окончено.
    Done,
    /// Код ошибки ядра (отрицательный `errno`); 0 — подтверждение.
    Status(i32),
    /// Чужое сообщение.
    Other,
}

/// Разбирает ответ ядра на сообщения; обрывок в конце отбрасывается.
pub(super) fn replies(buffer: &[u8]) -> Vec<Reply> {
    let mut found = Vec::new();
    let mut offset = 0;
    while let Some(header) = buffer.get(offset..offset + HEADER_LEN) {
        let length = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let kind = u16::from_ne_bytes([header[4], header[5]]);
        let Some(payload) = buffer.get(offset + HEADER_LEN..offset + length.max(HEADER_LEN)) else {
            break;
        };
        found.push(match kind {
            NLMSG_DONE => Reply::Done,
            NLMSG_ERROR => payload.get(..4).map_or(Reply::Other, |code| {
                Reply::Status(i32::from_ne_bytes([code[0], code[1], code[2], code[3]]))
            }),
            SOCK_DIAG_BY_FAMILY => payload
                .get(MESSAGE_ID_OFFSET..MESSAGE_ID_OFFSET + ID_LEN)
                .and_then(|id| id.try_into().ok())
                .map_or(Reply::Other, Reply::Socket),
            _ => Reply::Other,
        });
        if length < HEADER_LEN {
            break;
        }
        offset += (length + 3) & !3;
    }
    found
}

/// Удалённый адрес сокета: порт и адрес лежат в сетевом порядке.
pub(super) fn remote_of(id: &SocketId) -> SocketAddrV4 {
    let port = u16::from_be_bytes([id[2], id[3]]);
    let address = Ipv4Addr::new(id[20], id[21], id[22], id[23]);
    SocketAddrV4::new(address, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Сокет 10.0.0.2:50000 → 93.184.216.34:443, как его кладёт ядро.
    fn recorded_id() -> SocketId {
        let mut id = [0u8; ID_LEN];
        id[0..2].copy_from_slice(&50000u16.to_be_bytes());
        id[2..4].copy_from_slice(&443u16.to_be_bytes());
        id[4..8].copy_from_slice(&[10, 0, 0, 2]);
        id[20..24].copy_from_slice(&[93, 184, 216, 34]);
        id[40..48].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        id
    }

    fn message(kind: u16, payload: &[u8]) -> Vec<u8> {
        let length = u32::try_from(HEADER_LEN + payload.len()).expect("длина");
        let mut bytes = length.to_ne_bytes().to_vec();
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&[0; 10]);
        bytes.extend_from_slice(payload);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }

    #[test]
    fn the_request_has_the_layout_the_kernel_expects() {
        let id = recorded_id();
        let bytes = request(SOCK_DESTROY, NLM_F_ACK, u32::MAX, &id);

        assert_eq!(bytes.len(), 72);
        assert_eq!(
            u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            72
        );
        assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]), SOCK_DESTROY);
        assert_eq!(
            u16::from_ne_bytes([bytes[6], bytes[7]]),
            NLM_F_ACK | NLM_F_REQUEST
        );
        assert_eq!(&bytes[16..18], &[2, 6], "AF_INET и IPPROTO_TCP");
        assert_eq!(&bytes[24..], &id, "опознание с cookie уходит как пришло");
    }

    #[test]
    fn a_dump_asks_for_live_connections_only() {
        let bytes = request(SOCK_DIAG_BY_FAMILY, NLM_F_DUMP, LIVE_STATES, &[0; ID_LEN]);

        assert_eq!(
            u16::from_ne_bytes([bytes[6], bytes[7]]),
            NLM_F_DUMP | NLM_F_REQUEST
        );
        // TCP_ESTABLISHED (1) и TCP_SYN_SENT (2); LISTEN (10) не трогается.
        assert_eq!(
            u32::from_ne_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            0b110
        );
    }

    #[test]
    fn a_dump_yields_sockets_until_done() {
        let mut payload = vec![2, 1, 0, 0];
        payload.extend_from_slice(&recorded_id());
        payload.extend_from_slice(&[0; 20]);

        let mut buffer = message(SOCK_DIAG_BY_FAMILY, &payload);
        buffer.extend(message(NLMSG_DONE, &[0; 4]));

        assert_eq!(
            replies(&buffer),
            [Reply::Socket(recorded_id()), Reply::Done]
        );
    }

    #[test]
    fn an_error_code_is_read_back() {
        // EOPNOTSUPP в Linux.
        let buffer = message(NLMSG_ERROR, &(-95i32).to_ne_bytes());
        assert_eq!(replies(&buffer), [Reply::Status(-95)]);
    }

    #[test]
    fn a_truncated_tail_is_dropped() {
        let mut buffer = message(NLMSG_DONE, &[0; 4]);
        buffer.extend_from_slice(&[200, 0, 0, 0, 20, 0]);
        assert_eq!(replies(&buffer), [Reply::Done]);
    }

    #[test]
    fn the_remote_end_is_decoded_from_network_order() {
        assert_eq!(
            remote_of(&recorded_id()),
            "93.184.216.34:443".parse().expect("адрес")
        );
    }
}
