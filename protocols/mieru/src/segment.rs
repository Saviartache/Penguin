//! Сборка и разбор одного сегмента поверх шифра направления.
//!
//! Сетевого чтения здесь нет: сегмент читается в несколько приёмов — сперва
//! ровно [`metadata_block_len`] байт, чтобы узнать, сколько дальше дополнения
//! и полезной нагрузки, — и эту многошаговость обязан вести тот, кто держит
//! сокет (`underlay`). Здесь — только то, что не знает о сети: как из уже
//! снятых с провода байт получить открытый текст, и наоборот.
//!
//! Дополнение (`padding 0/1/2` из `docs/protocol.md`) этот крейт всегда шлёт
//! нулевой длины — своя схема обфускации трафика эталона не реализована (см.
//! документ крейта). Нулевая длина законна по формату: поля дополнения
//! помечены в спецификации необязательными.

use crate::cipher::{RecvCipher, SendCipher, TAG_LEN};
use crate::error::{MieruError, MieruResult};
use crate::metadata::{self, Metadata};
use crate::nonce;

/// Наибольший кусок полезной нагрузки в одном сегменте в режиме TCP.
///
/// Эталон делит более длинную запись на несколько сегментов; мы вместо этого
/// возвращаем из `poll_write` меньше байт, чем попросили, — это законно для
/// `AsyncWrite`, и заставляет каждый сегмент нести не больше одного куска.
pub const MAX_FRAGMENT: usize = 32_768;

/// Сколько байт снять с провода, чтобы получить метаданные следующего
/// сегмента. Отличается на длину нонса — она есть только у самого первого
/// сегмента направления.
pub fn metadata_block_len(expects_wire_nonce: bool) -> usize {
    let nonce_len = if expects_wire_nonce { nonce::LEN } else { 0 };
    nonce_len + metadata::LEN + TAG_LEN
}

/// Сколько байт снять с провода для полезной нагрузки данной длины.
pub fn payload_block_len(payload_len: u16) -> usize {
    usize::from(payload_len) + TAG_LEN
}

/// Собирает сегмент: метаданные и, если она есть, полезная нагрузка.
///
/// `metadata_bytes` уже должны нести верную `payload_len` — здесь это не
/// проверяется, потому что сборщик метаданных (`underlay`) и так не может
/// написать других байт: они считаются от той же `payload`.
pub fn write(
    send: &mut SendCipher,
    metadata_bytes: &[u8; metadata::LEN],
    payload: &[u8],
) -> MieruResult<Vec<u8>> {
    if payload.len() > MAX_FRAGMENT {
        return Err(MieruError::malformed(format!(
            "кусок в {} байт длиннее предела {MAX_FRAGMENT}",
            payload.len()
        )));
    }

    let mut out =
        Vec::with_capacity(nonce::LEN + metadata::LEN + TAG_LEN + payload.len() + TAG_LEN);
    send.seal(metadata_bytes, &mut out)?;
    if !payload.is_empty() {
        send.seal(payload, &mut out)?;
    }
    Ok(out)
}

/// Разбирает блок метаданных длиной [`metadata_block_len`], снятый с провода.
pub fn read_metadata(recv: &mut RecvCipher, block: &[u8]) -> MieruResult<Metadata> {
    let (wire_nonce, ciphertext) = if recv.expects_wire_nonce() {
        if block.len() < nonce::LEN {
            return Err(MieruError::malformed("блок метаданных короче нонса"));
        }
        let (n, rest) = block.split_at(nonce::LEN);
        (Some(n), rest)
    } else {
        (None, block)
    };

    let plain = recv.open(wire_nonce, ciphertext)?;
    let array: [u8; metadata::LEN] = plain.as_slice().try_into().map_err(|_| {
        MieruError::malformed(format!(
            "метаданные длиной {} байт вместо {}",
            plain.len(),
            metadata::LEN
        ))
    })?;
    Metadata::decode(&array)
}

/// Разбирает блок полезной нагрузки длиной [`payload_block_len`].
pub fn read_payload(recv: &mut RecvCipher, block: &[u8]) -> MieruResult<Vec<u8>> {
    recv.open(None, block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keying::Key;
    use crate::metadata::{DataAckKind, DataAckMetadata};

    fn key() -> Key {
        [3u8; 32]
    }

    fn sample() -> DataAckMetadata {
        DataAckMetadata {
            kind: DataAckKind::DataToServer,
            timestamp_minutes: 1,
            session_id: 42,
            seq: 0,
            unack_seq: 0,
            window_size: 4096,
            fragment: 0,
            prefix_len: 0,
            payload_len: 5,
            suffix_len: 0,
        }
    }

    #[test]
    fn a_segment_with_payload_survives_the_round_trip() {
        let mut send = SendCipher::new(&key(), "alice");
        let mut recv = RecvCipher::new(&key());

        let meta = sample();
        let wire = write(&mut send, &meta.encode(), b"hello").expect("собирается");

        let m_len = metadata_block_len(recv.expects_wire_nonce());
        let (m_block, rest) = wire.split_at(m_len);
        let decoded = read_metadata(&mut recv, m_block).expect("метаданные читаются");
        assert_eq!(decoded, Metadata::DataAck(meta));

        let p_len = payload_block_len(decoded.payload_len());
        assert_eq!(rest.len(), p_len, "во второй части ровно полезная нагрузка");
        let payload = read_payload(&mut recv, rest).expect("нагрузка читается");
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn a_segment_without_payload_is_just_the_metadata_block() {
        let mut send = SendCipher::new(&key(), "alice");
        let mut recv = RecvCipher::new(&key());

        let mut meta = sample();
        meta.payload_len = 0;
        let wire = write(&mut send, &meta.encode(), &[]).expect("собирается");

        assert_eq!(wire.len(), metadata_block_len(true));
        let decoded = read_metadata(&mut recv, &wire).expect("метаданные читаются");
        assert_eq!(decoded.payload_len(), 0);
    }

    #[test]
    fn only_the_very_first_segment_of_a_direction_carries_a_nonce() {
        let mut send = SendCipher::new(&key(), "alice");
        let meta = sample();

        let first = write(&mut send, &meta.encode(), b"one").expect("собирается");
        let second = write(&mut send, &meta.encode(), b"two").expect("собирается");

        assert_eq!(first.len(), metadata_block_len(true) + payload_block_len(3));
        assert_eq!(
            second.len(),
            metadata_block_len(false) + payload_block_len(3)
        );
    }

    #[test]
    fn a_fragment_bigger_than_the_limit_is_refused() {
        let mut send = SendCipher::new(&key(), "alice");
        let meta = sample();
        let oversized = vec![0u8; MAX_FRAGMENT + 1];
        assert!(write(&mut send, &meta.encode(), &oversized).is_err());
    }

    #[test]
    fn a_tampered_metadata_block_is_rejected() {
        let mut send = SendCipher::new(&key(), "alice");
        let mut recv = RecvCipher::new(&key());

        let meta = sample();
        let mut wire = write(&mut send, &meta.encode(), b"hello").expect("собирается");
        let m_len = metadata_block_len(true);
        // Портим последний байт именно блока метаданных — байт дальше него
        // принадлежит уже полезной нагрузке и этот тест не проверял бы то,
        // что заявлено в названии.
        wire[m_len - 1] ^= 1;

        assert!(read_metadata(&mut recv, &wire[..m_len]).is_err());
    }
}
