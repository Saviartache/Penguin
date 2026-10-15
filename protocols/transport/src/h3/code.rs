//! Коды ошибок и типы однонаправленных потоков HTTP/3.

/// Типы однонаправленных потоков (RFC 9114, §6.2; RFC 9204, §4.2).
pub mod stream_type {
    /// Поток управления.
    pub const CONTROL: u64 = 0x00;
    /// Поток проталкивания.
    pub const PUSH: u64 = 0x01;
    /// Поток кодировщика QPACK.
    pub const QPACK_ENCODER: u64 = 0x02;
    /// Поток декодировщика QPACK.
    pub const QPACK_DECODER: u64 = 0x03;
}

/// Ошибки нет: соединение или поток закрыты штатно.
pub const H3_NO_ERROR: u64 = 0x0100;
/// Собеседник нарушил протокол, точнее не сказать.
pub const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x0101;
/// Внутренняя ошибка.
pub const H3_INTERNAL_ERROR: u64 = 0x0102;
/// Поток, которого собеседник открывать не вправе.
pub const H3_STREAM_CREATION_ERROR: u64 = 0x0103;
/// Закрыт поток, без которого соединение не живёт.
pub const H3_CLOSED_CRITICAL_STREAM: u64 = 0x0104;
/// Кадр не на своём месте.
pub const H3_FRAME_UNEXPECTED: u64 = 0x0105;
/// Кадр не разбирается.
pub const H3_FRAME_ERROR: u64 = 0x0106;
/// Собеседник нагружает сверх разумного.
pub const H3_EXCESSIVE_LOAD: u64 = 0x0107;
/// Номер потока или проталкивания использован неверно.
pub const H3_ID_ERROR: u64 = 0x0108;
/// Ошибка в `SETTINGS`.
pub const H3_SETTINGS_ERROR: u64 = 0x0109;
/// Первым кадром потока управления пришёл не `SETTINGS`.
pub const H3_MISSING_SETTINGS: u64 = 0x010a;
/// Запрос отменён.
pub const H3_REQUEST_CANCELLED: u64 = 0x010c;
/// Сообщение построено неверно.
pub const H3_MESSAGE_ERROR: u64 = 0x010e;
/// TCP-соединение за `CONNECT` сброшено или упало.
pub const H3_CONNECT_ERROR: u64 = 0x010f;
/// Блок полей не разобрался (RFC 9204, §6).
pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x0200;
/// Датаграмма HTTP построена неверно (RFC 9297, §2.1).
pub const H3_DATAGRAM_ERROR: u64 = 0x33;
