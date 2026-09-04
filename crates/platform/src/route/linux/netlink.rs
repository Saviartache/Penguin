//! Разговор с ядром на языке netlink.
//!
//! Не `ip route`: маршруты — то, чем тоннель забирает трафик, и снимать их
//! обязательно даже по аварийному пути. Зависеть в этом от чужой программы,
//! которой в системе может не оказаться, а вывод которой к тому же
//! переводится, нельзя.
//!
//! Заголовки объявлены здесь, а не взяты из `libc`: их там нет, а сама
//! раскладка — двоичный договор ядра с программами, собранными десятилетия
//! назад, и не меняется.

use crate::error::{PlatformError, PlatformResult};

/// Это запрос.
pub(super) const NLM_F_REQUEST: u16 = 0x001;
/// Ответить, даже если всё получилось: молчание ядра нам не годится —
/// неудача снятия маршрута обязана быть заметной.
pub(super) const NLM_F_ACK: u16 = 0x004;
/// Не подменять существующий маршрут.
pub(super) const NLM_F_EXCL: u16 = 0x200;
/// Создать, если его нет.
pub(super) const NLM_F_CREATE: u16 = 0x400;

/// Ответ с кодом ошибки. Он же — подтверждение с нулём вместо кода.
const NLMSG_ERROR: u16 = 2;

/// Длина заголовка сообщения.
const HEADER_LEN: usize = 16;
/// Длина описания маршрута.
const ROUTE_LEN: usize = 12;

/// Заголовок сообщения netlink.
#[repr(C)]
#[derive(Clone, Copy)]
struct MessageHeader {
    length: u32,
    kind: u16,
    flags: u16,
    sequence: u32,
    port: u32,
}

/// Описание маршрута.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct RouteHeader {
    /// Семейство адресов.
    pub(super) family: u8,
    /// Длина префикса назначения.
    pub(super) destination_len: u8,
    /// Длина префикса источника. Всегда ноль: источник мы не сужаем.
    pub(super) source_len: u8,
    /// Тип обслуживания. Не используется.
    pub(super) tos: u8,
    /// Таблица маршрутизации.
    pub(super) table: u8,
    /// Кто поставил маршрут.
    pub(super) protocol: u8,
    /// Насколько далеко он ведёт.
    pub(super) scope: u8,
    /// Вид маршрута.
    pub(super) kind: u8,
    /// Флаги. Не используются.
    pub(super) flags: u32,
}

/// Собираемое сообщение.
pub(super) struct Message {
    buffer: Vec<u8>,
}

impl Message {
    /// Начинает сообщение о маршруте.
    pub(super) fn new(kind: u16, flags: u16, route: &RouteHeader) -> Self {
        let header = MessageHeader {
            length: 0,
            kind,
            flags: flags | NLM_F_REQUEST,
            // Порядковый номер и порт заполняет отправка: одному сообщению —
            // один номер, и следить за ним удобнее в одном месте.
            sequence: 0,
            port: 0,
        };

        let mut buffer = Vec::with_capacity(HEADER_LEN + ROUTE_LEN + 64);
        buffer.extend_from_slice(bytes_of(&header));
        buffer.extend_from_slice(bytes_of(route));
        Self { buffer }
    }

    /// Дописывает свойство маршрута.
    ///
    /// Каждое выровнено по четыре байта — так его читает ядро. Без выравнивания
    /// оно прочитает следующее свойство со сдвигом и вернёт `EINVAL`.
    pub(super) fn attribute(&mut self, kind: u16, value: &[u8]) {
        let length = 4 + value.len();
        #[allow(
            clippy::cast_possible_truncation,
            reason = "свойство маршрута заведомо короче 64 КиБ"
        )]
        self.buffer
            .extend_from_slice(&(length as u16).to_ne_bytes());
        self.buffer.extend_from_slice(&kind.to_ne_bytes());
        self.buffer.extend_from_slice(value);
        self.buffer.resize(align(self.buffer.len()), 0);
    }

    /// Проставляет длину и отдаёт готовые байты.
    pub(super) fn finish(mut self, sequence: u32) -> Vec<u8> {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "сообщение о маршруте заведомо короче 4 ГиБ"
        )]
        let length = (self.buffer.len() as u32).to_ne_bytes();
        self.buffer[..4].copy_from_slice(&length);
        self.buffer[8..12].copy_from_slice(&sequence.to_ne_bytes());
        self.buffer
    }
}

/// Выравнивает длину по четыре байта.
const fn align(length: usize) -> usize {
    (length + 3) & !3
}

/// Байты структуры как они лягут в сообщение.
fn bytes_of<T: Copy>(value: &T) -> &[u8] {
    #[allow(unsafe_code, reason = "заголовок netlink передаётся ядру как есть")]
    unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(value).cast::<u8>(),
            std::mem::size_of::<T>(),
        )
    }
}

/// Отправляет сообщение и возвращает ответ.
pub(super) fn talk(message: Message) -> PlatformResult<Vec<u8>> {
    use std::os::fd::AsRawFd;

    use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType};

    let socket = nix::sys::socket::socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::empty(),
        // `None` — протокол ноль, а ноль в семействе netlink и есть
        // подсистема маршрутизации (`NETLINK_ROUTE`). Отдельного варианта под
        // неё в `nix` нет.
        None,
    )
    .map_err(|err| PlatformError::Route(format!("сокет netlink: {err}")))?;

    // Номер нужен только чтобы отличить свой ответ от чужого; часов хватает.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "от времени нужен лишь неповторяющийся хвост"
    )]
    let sequence = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos() as u32)
        .unwrap_or(1);
    let request = message.finish(sequence);

    nix::sys::socket::send(socket.as_raw_fd(), &request, MsgFlags::empty())
        .map_err(|err| PlatformError::Route(format!("запрос к ядру: {err}")))?;

    let mut reply = vec![0u8; 8192];
    let read = nix::sys::socket::recv(socket.as_raw_fd(), &mut reply, MsgFlags::empty())
        .map_err(|err| PlatformError::Route(format!("ответ ядра: {err}")))?;
    reply.truncate(read);

    check(&reply)?;
    Ok(reply)
}

/// Проверяет ответ ядра.
///
/// Подтверждение приходит тем же сообщением, что и ошибка: нулём вместо кода.
fn check(reply: &[u8]) -> PlatformResult<()> {
    let Some(kind) = reply.get(4..6) else {
        return Err(PlatformError::Route("ядро ответило пустотой".to_owned()));
    };
    let kind = u16::from_ne_bytes([kind[0], kind[1]]);
    if kind != NLMSG_ERROR {
        return Ok(());
    }

    let Some(code) = reply.get(HEADER_LEN..HEADER_LEN + 4) else {
        return Err(PlatformError::Route("ответ ядра оборван".to_owned()));
    };
    let code = i32::from_ne_bytes([code[0], code[1], code[2], code[3]]);
    if code == 0 {
        return Ok(());
    }

    let err = std::io::Error::from_raw_os_error(-code);
    Err(match -code {
        libc::EPERM | libc::EACCES => {
            PlatformError::PermissionDenied("изменение таблицы маршрутизации".to_owned())
        }
        _ => PlatformError::Route(err.to_string()),
    })
}

/// Перебирает свойства, приложенные к сообщению.
///
/// Возвращает пары «вид, значение». Ответ ядра — чужие данные, и обрыв в
/// середине здесь обычное дело: перебор просто заканчивается.
pub(super) fn attributes(payload: &[u8]) -> Vec<(u16, &[u8])> {
    let mut found = Vec::new();
    let mut offset = 0;

    while offset + 4 <= payload.len() {
        let length = usize::from(u16::from_ne_bytes([payload[offset], payload[offset + 1]]));
        let kind = u16::from_ne_bytes([payload[offset + 2], payload[offset + 3]]);
        if length < 4 || offset + length > payload.len() {
            break;
        }
        found.push((kind, &payload[offset + 4..offset + length]));
        offset += align(length);
    }
    found
}

/// Полезная часть ответа о маршруте: всё, что идёт после двух заголовков.
pub(super) fn route_payload(reply: &[u8]) -> Option<&[u8]> {
    reply.get(HEADER_LEN + ROUTE_LEN..)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_are_the_size_the_kernel_expects() {
        // Разойдясь с ядром на байт, мы получим `EINVAL` без единого намёка
        // на причину.
        assert_eq!(std::mem::size_of::<MessageHeader>(), HEADER_LEN);
        assert_eq!(std::mem::size_of::<RouteHeader>(), ROUTE_LEN);
    }

    #[test]
    fn attributes_are_aligned_to_four_bytes() {
        // Без выравнивания ядро читает следующее свойство со сдвигом.
        let mut message = Message::new(0, 0, &RouteHeader::default());
        message.attribute(1, &[1, 2, 3]);
        message.attribute(2, &[4, 5, 6, 7]);

        let bytes = message.finish(7);
        assert_eq!(bytes.len() % 4, 0);
        // Первое свойство занимает 4 + 3 = 7 байт и дополняется до восьми.
        assert_eq!(bytes.len(), HEADER_LEN + ROUTE_LEN + 8 + 8);
    }

    #[test]
    fn the_length_and_sequence_land_in_the_header() {
        let bytes = Message::new(24, NLM_F_ACK, &RouteHeader::default()).finish(0x0102_0304);
        assert_eq!(
            u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
            bytes.len()
        );
        assert_eq!(
            u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            0x0102_0304
        );
    }

    #[test]
    fn a_request_flag_is_always_set() {
        // Без него ядро считает сообщение уведомлением и молча его роняет.
        let bytes = Message::new(24, NLM_F_ACK, &RouteHeader::default()).finish(1);
        let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
        assert_eq!(flags & NLM_F_REQUEST, NLM_F_REQUEST);
    }

    #[test]
    fn a_zero_code_is_an_acknowledgement() {
        // Подтверждение приходит тем же сообщением, что и ошибка.
        let mut reply = vec![0u8; HEADER_LEN + 4];
        reply[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        check(&reply).expect("ноль означает успех");
    }

    #[test]
    fn a_permission_error_is_recognisable() {
        let mut reply = vec![0u8; HEADER_LEN + 4];
        reply[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        reply[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&(-libc::EPERM).to_ne_bytes());

        let err = check(&reply).expect_err("отказ");
        assert!(err.needs_privileges(), "{err}");
    }

    #[test]
    fn attributes_stop_at_a_truncated_tail() {
        // Ответ ядра — чужие данные; обрыв в середине не должен приводить к
        // панике.
        let payload = [8u8, 0, 5, 0, 1, 2, 3, 4, 200, 0];
        let found = attributes(&payload);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], (5, &[1, 2, 3, 4][..]));
    }
}
