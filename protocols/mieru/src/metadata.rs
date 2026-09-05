//! Метаданные сегмента: 32 открытых (после расшифровки) байта, которые есть
//! в каждом сегменте.
//!
//! Два вида, оба зеркалят `pkg/protocol/metadata.go` эталона побайтно:
//!
//! ```text
//! sessionStruct (открытие и закрытие сессии)
//! +----------+--------+-----------+-----------+-----------+------+--------+-----------+---------+
//! | protocol | unused | timestamp | sessionID | seq       | code | payloadLen | suffixLen | unused |
//! +----------+--------+-----------+-----------+-----------+------+--------+-----------+---------+
//! |    1     |   1    |    4      |    4      |    4      |  1   |    2   |     1      |   14   |
//! +----------+--------+-----------+-----------+-----------+------+--------+-----------+---------+
//!
//! dataAckStruct (данные и подтверждения)
//! +----------+--------+-----------+-----------+-----+---------+--------+----------+-----------+--------+-----------+--------+
//! | protocol | unused | timestamp | sessionID | seq | unAckSeq| window | fragment | prefixLen | payloadLen | suffixLen | unused |
//! +----------+--------+-----------+-----------+-----+---------+--------+----------+-----------+--------+-----------+--------+
//! |    1     |   1    |    4      |    4      |  4  |    4    |   2    |    1     |     1     |    2   |     1     |   7    |
//! +----------+--------+-----------+-----------+-----+---------+--------+----------+-----------+--------+-----------+--------+
//! ```
//!
//! Расширение с низкой энтропией (`lowEntropyMode` вместо `unused`, типы
//! протокола 10 и 11) здесь не реализовано — это отдельный, необязательный
//! способ обфускации, а не часть базового формата (см. документ крейта).

use crate::error::{MieruError, MieruResult};

/// Длина метаданных.
pub const LEN: usize = 32;

/// Вид сегмента, управляющего сессией.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// Клиент просит открыть сессию.
    OpenRequest,
    /// Сервер подтверждает открытие.
    OpenResponse,
    /// Просьба закрыть сессию.
    CloseRequest,
    /// Подтверждение закрытия.
    CloseResponse,
}

impl SessionKind {
    fn byte(self) -> u8 {
        match self {
            Self::OpenRequest => 2,
            Self::OpenResponse => 3,
            Self::CloseRequest => 4,
            Self::CloseResponse => 5,
        }
    }

    fn parse(byte: u8) -> Option<Self> {
        match byte {
            2 => Some(Self::OpenRequest),
            3 => Some(Self::OpenResponse),
            4 => Some(Self::CloseRequest),
            5 => Some(Self::CloseResponse),
            _ => None,
        }
    }
}

/// Код ответа на открытие сессии.
pub const STATUS_OK: u8 = 0;
/// Сервер отказал: исчерпана квота пользователя.
pub const STATUS_QUOTA_EXHAUSTED: u8 = 1;

/// Метаданные сегмента, управляющего сессией.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionMetadata {
    /// Вид сегмента.
    pub kind: SessionKind,
    /// Минут с начала эпохи.
    pub timestamp_minutes: u32,
    /// Номер сессии.
    pub session_id: u32,
    /// Порядковый номер этого сегмента в сессии.
    pub seq: u32,
    /// Код ответа. Осмыслен только у [`SessionKind::OpenResponse`].
    pub status: u8,
    /// Длина полезной нагрузки, если она приложена к этому сегменту.
    pub payload_len: u16,
    /// Длина хвостового дополнения.
    pub suffix_len: u8,
}

impl SessionMetadata {
    /// Записывает метаданные.
    pub fn encode(&self) -> [u8; LEN] {
        let mut out = [0u8; LEN];
        out[0] = self.kind.byte();
        out[2..6].copy_from_slice(&self.timestamp_minutes.to_be_bytes());
        out[6..10].copy_from_slice(&self.session_id.to_be_bytes());
        out[10..14].copy_from_slice(&self.seq.to_be_bytes());
        out[14] = self.status;
        out[15..17].copy_from_slice(&self.payload_len.to_be_bytes());
        out[17] = self.suffix_len;
        out
    }

    fn decode(bytes: &[u8; LEN], kind: SessionKind) -> Self {
        Self {
            kind,
            timestamp_minutes: u32::from_be_bytes(bytes[2..6].try_into().unwrap_or_default()),
            session_id: u32::from_be_bytes(bytes[6..10].try_into().unwrap_or_default()),
            seq: u32::from_be_bytes(bytes[10..14].try_into().unwrap_or_default()),
            status: bytes[14],
            payload_len: u16::from_be_bytes(bytes[15..17].try_into().unwrap_or_default()),
            suffix_len: bytes[17],
        }
    }
}

/// Вид сегмента с данными или подтверждением.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAckKind {
    /// Данные от клиента к серверу.
    DataToServer,
    /// Данные от сервера к клиенту.
    DataToClient,
    /// Подтверждение от клиента.
    AckFromClient,
    /// Подтверждение от сервера.
    AckFromServer,
}

impl DataAckKind {
    fn byte(self) -> u8 {
        match self {
            Self::DataToServer => 6,
            Self::DataToClient => 7,
            Self::AckFromClient => 8,
            Self::AckFromServer => 9,
        }
    }

    fn parse(byte: u8) -> Option<Self> {
        match byte {
            6 => Some(Self::DataToServer),
            7 => Some(Self::DataToClient),
            8 => Some(Self::AckFromClient),
            9 => Some(Self::AckFromServer),
            _ => None,
        }
    }
}

/// Метаданные сегмента с данными или подтверждением.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataAckMetadata {
    /// Вид сегмента.
    pub kind: DataAckKind,
    /// Минут с начала эпохи.
    pub timestamp_minutes: u32,
    /// Номер сессии.
    pub session_id: u32,
    /// Порядковый номер этого сегмента.
    pub seq: u32,
    /// Номер следующего ожидаемого сегмента — совокупное подтверждение.
    pub unack_seq: u32,
    /// Сколько ещё сегментов готов принять отправитель этого сегмента.
    pub window_size: u16,
    /// Здесь не используется (см. документ крейта) — всегда `0`.
    pub fragment: u8,
    /// Длина дополнения перед полезной нагрузкой.
    pub prefix_len: u8,
    /// Длина полезной нагрузки.
    pub payload_len: u16,
    /// Длина дополнения после полезной нагрузки.
    pub suffix_len: u8,
}

impl DataAckMetadata {
    /// Записывает метаданные.
    pub fn encode(&self) -> [u8; LEN] {
        let mut out = [0u8; LEN];
        out[0] = self.kind.byte();
        out[2..6].copy_from_slice(&self.timestamp_minutes.to_be_bytes());
        out[6..10].copy_from_slice(&self.session_id.to_be_bytes());
        out[10..14].copy_from_slice(&self.seq.to_be_bytes());
        out[14..18].copy_from_slice(&self.unack_seq.to_be_bytes());
        out[18..20].copy_from_slice(&self.window_size.to_be_bytes());
        out[20] = self.fragment;
        out[21] = self.prefix_len;
        out[22..24].copy_from_slice(&self.payload_len.to_be_bytes());
        out[24] = self.suffix_len;
        out
    }

    fn decode(bytes: &[u8; LEN], kind: DataAckKind) -> Self {
        Self {
            kind,
            timestamp_minutes: u32::from_be_bytes(bytes[2..6].try_into().unwrap_or_default()),
            session_id: u32::from_be_bytes(bytes[6..10].try_into().unwrap_or_default()),
            seq: u32::from_be_bytes(bytes[10..14].try_into().unwrap_or_default()),
            unack_seq: u32::from_be_bytes(bytes[14..18].try_into().unwrap_or_default()),
            window_size: u16::from_be_bytes(bytes[18..20].try_into().unwrap_or_default()),
            fragment: bytes[20],
            prefix_len: bytes[21],
            payload_len: u16::from_be_bytes(bytes[22..24].try_into().unwrap_or_default()),
            suffix_len: bytes[24],
        }
    }
}

/// Метаданные любого из двух видов.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metadata {
    /// Управление сессией: открытие, закрытие.
    Session(SessionMetadata),
    /// Данные или подтверждение.
    DataAck(DataAckMetadata),
}

impl Metadata {
    /// Разбирает 32 байта метаданных.
    ///
    /// `Err` — байт протокола не входит ни в один известный вид. Сюда же
    /// попадают типы 10 и 11 (расширение с низкой энтропией): мы их не
    /// реализуем и не притворяемся, что поняли.
    pub fn decode(bytes: &[u8; LEN]) -> MieruResult<Self> {
        if let Some(kind) = SessionKind::parse(bytes[0]) {
            return Ok(Self::Session(SessionMetadata::decode(bytes, kind)));
        }
        if let Some(kind) = DataAckKind::parse(bytes[0]) {
            return Ok(Self::DataAck(DataAckMetadata::decode(bytes, kind)));
        }
        Err(MieruError::malformed(format!(
            "неизвестный тип протокола {}",
            bytes[0]
        )))
    }

    /// Номер сессии, к которой относится сегмент.
    pub fn session_id(&self) -> u32 {
        match self {
            Self::Session(meta) => meta.session_id,
            Self::DataAck(meta) => meta.session_id,
        }
    }

    /// Длина полезной нагрузки, объявленная в метаданных.
    pub fn payload_len(&self) -> u16 {
        match self {
            Self::Session(meta) => meta.payload_len,
            Self::DataAck(meta) => meta.payload_len,
        }
    }

    /// Длина дополнения перед полезной нагрузкой. У сегментов сессии его
    /// не бывает — поля для него просто нет в формате.
    pub fn prefix_len(&self) -> u8 {
        match self {
            Self::Session(_) => 0,
            Self::DataAck(meta) => meta.prefix_len,
        }
    }

    /// Длина дополнения после полезной нагрузки.
    pub fn suffix_len(&self) -> u8 {
        match self {
            Self::Session(meta) => meta.suffix_len,
            Self::DataAck(meta) => meta.suffix_len,
        }
    }

    /// Минут с начала эпохи, записанных отправителем.
    pub fn timestamp_minutes(&self) -> u32 {
        match self {
            Self::Session(meta) => meta.timestamp_minutes,
            Self::DataAck(meta) => meta.timestamp_minutes,
        }
    }
}

/// Метка времени не разошлась с часами больше чем на минуту в обе стороны.
///
/// Разница считается по кругу: `u32` минут переполняется через восемь тысяч
/// лет, и на практике это не сокращение точности, а защита от паники на
/// вычитании, если чужой сегмент вдруг придёт с мусором вместо времени.
pub fn timestamp_within_range(current_minutes: u32, given_minutes: u32) -> bool {
    let diff = current_minutes.wrapping_sub(given_minutes);
    diff == 0 || diff == 1 || diff == u32::MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_header_survives_the_round_trip() {
        let meta = SessionMetadata {
            kind: SessionKind::OpenRequest,
            timestamp_minutes: 0x0102_0304,
            session_id: 0x0506_0708,
            seq: 0x090a_0b0c,
            status: 0,
            payload_len: 7,
            suffix_len: 3,
        };
        let bytes = meta.encode();
        assert_eq!(
            Metadata::decode(&bytes).expect("разбирается"),
            Metadata::Session(meta)
        );
    }

    #[test]
    fn the_session_header_is_laid_out_the_way_the_reference_reads_it() {
        // Побайтно, а не только круговым прогоном: свой разбор согласится
        // сам с собой при любой ошибке в порядке полей.
        let meta = SessionMetadata {
            kind: SessionKind::OpenResponse,
            timestamp_minutes: 1,
            session_id: 2,
            seq: 3,
            status: STATUS_QUOTA_EXHAUSTED,
            payload_len: 0x0102,
            suffix_len: 9,
        };
        let bytes = meta.encode();
        assert_eq!(bytes[0], 3, "protocol");
        assert_eq!(bytes[1], 0, "unused");
        assert_eq!(&bytes[2..6], &[0, 0, 0, 1], "timestamp");
        assert_eq!(&bytes[6..10], &[0, 0, 0, 2], "sessionID");
        assert_eq!(&bytes[10..14], &[0, 0, 0, 3], "seq");
        assert_eq!(bytes[14], 1, "statusCode");
        assert_eq!(&bytes[15..17], &[0x01, 0x02], "payloadLen");
        assert_eq!(bytes[17], 9, "suffixLen");
    }

    #[test]
    fn a_data_ack_header_survives_the_round_trip() {
        let meta = DataAckMetadata {
            kind: DataAckKind::DataToServer,
            timestamp_minutes: 111,
            session_id: 222,
            seq: 333,
            unack_seq: 444,
            window_size: 4096,
            fragment: 0,
            prefix_len: 0,
            payload_len: 555,
            suffix_len: 0,
        };
        let bytes = meta.encode();
        assert_eq!(
            Metadata::decode(&bytes).expect("разбирается"),
            Metadata::DataAck(meta)
        );
    }

    #[test]
    fn the_data_ack_header_is_laid_out_the_way_the_reference_reads_it() {
        let meta = DataAckMetadata {
            kind: DataAckKind::AckFromServer,
            timestamp_minutes: 0,
            session_id: 0,
            seq: 1,
            unack_seq: 2,
            window_size: 4096,
            fragment: 0,
            prefix_len: 5,
            payload_len: 6,
            suffix_len: 7,
        };
        let bytes = meta.encode();
        assert_eq!(bytes[0], 9, "protocol");
        assert_eq!(&bytes[10..14], &[0, 0, 0, 1], "seq");
        assert_eq!(&bytes[14..18], &[0, 0, 0, 2], "unAckSeq");
        assert_eq!(&bytes[18..20], &[0x10, 0x00], "windowSize");
        assert_eq!(bytes[20], 0, "fragment");
        assert_eq!(bytes[21], 5, "prefixLen");
        assert_eq!(&bytes[22..24], &[0, 6], "payloadLen");
        assert_eq!(bytes[24], 7, "suffixLen");
    }

    #[test]
    fn an_unknown_protocol_byte_is_reported_not_guessed() {
        // Типы 10 и 11 (низкая энтропия) сюда тоже попадают: мы их не
        // реализуем и не хотим молча принять их байты за что-то другое.
        for byte in [0, 1, 10, 11, 255] {
            let mut bytes = [0u8; LEN];
            bytes[0] = byte;
            assert!(Metadata::decode(&bytes).is_err(), "byte={byte}");
        }
    }

    #[test]
    fn the_clock_check_allows_a_minute_either_way() {
        assert!(timestamp_within_range(100, 100));
        assert!(timestamp_within_range(100, 99));
        assert!(timestamp_within_range(100, 101));
        assert!(!timestamp_within_range(100, 98));
        assert!(!timestamp_within_range(100, 102));
    }

    #[test]
    fn the_clock_check_does_not_panic_across_the_wraparound() {
        assert!(timestamp_within_range(0, u32::MAX));
        assert!(timestamp_within_range(u32::MAX, 0));
    }
}
