//! Кадр тела: `[длина, 2 байта ⊕ маска] [кусок + метка AEAD] [дополнение]`.
//!
//! Маска длины (`0x04`) и длина дополнения (`0x08`, `% 64`) — слова одного потока
//! Shake128, засеянного `IV` тела; padding берётся до маски. Маска есть и у `none`.
//! Нонс куска (AES-GCM, ChaCha): `counter(2, BE) || IV[2..12]`, счётчик с нуля на кусок
//! (`GenerateChunkNonce`, `proxy/vmess/encoding/client.go`, `v2fly/v2ray-core`).
//! Кусок без данных (длина кадра = метка + дополнение) — терминатор, проверяется до расшифровки.

use bytes::{BufMut, BytesMut};
use penguin_proto::random;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::crypto::security::Wire;
use crate::error::{VmessError, VmessResult};

/// Предел куска при записи: `0xFFFF` минус метка (16) и наибольшее дополнение (63).
/// Датаграмма обязана уйти одним куском, поэтому предел впритык.
pub const MAX_PLAINTEXT: usize = 0xFFFF - 16 - 63;

/// Сколько байт кадра ждать после поля длины.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkLength {
    /// Всего байт после поля длины: кусок, метка, дополнение.
    pub on_wire: usize,
    /// Из них кусок с меткой, без дополнения; столько ждёт [`BodyCipher::open_chunk`].
    pub ciphertext: usize,
}

/// Шифр одного направления одного соединения.
pub struct BodyCipher {
    aead: Option<Aead>,
    mask: Shake128Xof,
    padded: bool,
    tag_len: usize,
}

/// AEAD-часть: только у AES-128-GCM и ChaCha20-Poly1305.
struct Aead {
    key: LessSafeKey,
    iv_tail: [u8; 10],
    counter: u16,
}

impl BodyCipher {
    /// Шифр по ключу и `IV` тела этого направления; `Wire::Zero` сюда не доходит.
    pub fn new(wire: Wire, body_key: &[u8; 16], body_iv: &[u8; 16]) -> Self {
        let mut mask = Shake128::default();
        mask.update(body_iv);

        let aead = wire.ring_algorithm().map(|algorithm| {
            let key_bytes = wire.effective_key(body_key);
            let unbound = UnboundKey::new(algorithm, &key_bytes)
                .unwrap_or_else(|_| unreachable!("длина ключа задана самим `Wire`"));
            let mut iv_tail = [0u8; 10];
            iv_tail.copy_from_slice(&body_iv[2..12]);
            Aead {
                key: LessSafeKey::new(unbound),
                iv_tail,
                counter: 0,
            }
        });

        Self {
            aead,
            mask: Shake128Xof(mask.finalize_xof()),
            padded: wire.option_byte() & 0x08 != 0,
            tag_len: wire.tag_len(),
        }
    }

    /// Дописывает в `out` кадр целиком; пустой `plain` — терминатор. При ошибке `out` не меняется.
    pub fn seal_chunk(&mut self, plain: &[u8], out: &mut BytesMut) -> VmessResult<()> {
        let padding_len = self.next_padding_len();
        let sealed_len = plain.len() + self.tag_len;
        let declared = u16::try_from(sealed_len + padding_len)
            .map_err(|_| VmessError::Oversized(sealed_len + padding_len))?;
        let masked = declared ^ self.mask.next_u16();

        let frame_start = out.len();
        out.reserve(2 + sealed_len + padding_len);
        out.put_u16(masked);
        let body_start = out.len();
        out.extend_from_slice(plain);
        if let Some(aead) = &mut self.aead {
            let nonce = aead.next_nonce();
            match aead
                .key
                .seal_in_place_separate_tag(nonce, Aad::empty(), &mut out[body_start..])
            {
                Ok(tag) => out.extend_from_slice(tag.as_ref()),
                Err(_) => {
                    out.truncate(frame_start);
                    return Err(VmessError::malformed("кусок тела не зашифровался"));
                }
            }
        }
        if padding_len > 0 {
            let at = out.len();
            out.resize(at + padding_len, 0);
            fill_padding(&mut out[at..]);
        }
        Ok(())
    }

    /// Разбирает снятое с провода поле длины; `Ok(None)` — терминатор.
    pub fn decode_length(&mut self, masked: [u8; 2]) -> VmessResult<Option<ChunkLength>> {
        let padding_len = self.next_padding_len();
        let declared = usize::from(u16::from_be_bytes(masked) ^ self.mask.next_u16());
        let ciphertext = declared
            .checked_sub(padding_len)
            .ok_or_else(|| VmessError::malformed("кусок короче объявленного дополнения"))?;

        if ciphertext == self.tag_len {
            return Ok(None);
        }
        Ok(Some(ChunkLength {
            on_wire: declared,
            ciphertext,
        }))
    }

    /// Расшифровывает на месте; `frame` — ровно [`ChunkLength::ciphertext`] байт.
    pub fn open_chunk<'a>(&mut self, frame: &'a mut [u8]) -> VmessResult<&'a mut [u8]> {
        match &mut self.aead {
            Some(aead) => {
                let nonce = aead.next_nonce();
                aead.key
                    .open_in_place(nonce, Aad::empty(), frame)
                    .map_err(|_| VmessError::malformed("кусок тела не расшифровался"))
            }
            None => Ok(frame),
        }
    }

    /// Длина метки подлинности; ноль у `none`.
    pub fn tag_len(&self) -> usize {
        self.tag_len
    }

    fn next_padding_len(&mut self) -> usize {
        if self.padded {
            usize::from(self.mask.next_u16() % 64)
        } else {
            0
        }
    }
}

impl Aead {
    fn next_nonce(&mut self) -> Nonce {
        let mut bytes = [0u8; 12];
        bytes[..2].copy_from_slice(&self.counter.to_be_bytes());
        bytes[2..].copy_from_slice(&self.iv_tail);
        self.counter = self.counter.wrapping_add(1);
        Nonce::assume_unique_for_key(bytes)
    }
}

/// Дополнение идёт открытым текстом, криптостойкость не нужна.
fn fill_padding(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(8) {
        let word = random::u64().to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
}

/// Поток Shake128 по два байта (`ShakeSizeParser.next()` эталона).
struct Shake128Xof(sha3::Shake128Reader);

impl Shake128Xof {
    fn next_u16(&mut self) -> u16 {
        let mut buffer = [0u8; 2];
        self.0.read(&mut buffer);
        u16::from_be_bytes(buffer)
    }
}

#[cfg(test)]
pub(crate) fn seal_to_vec(cipher: &mut BodyCipher, plain: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::new();
    cipher.seal_chunk(plain, &mut out).expect("шифруется");
    out.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(wire: Wire) -> (BodyCipher, BodyCipher) {
        let key = [7u8; 16];
        let iv = [9u8; 16];
        (
            BodyCipher::new(wire, &key, &iv),
            BodyCipher::new(wire, &key, &iv),
        )
    }

    fn round_trip(wire: Wire) {
        let (mut send, mut recv) = pair(wire);
        let wire_bytes = seal_to_vec(&mut send, b"payload");

        let length_field: [u8; 2] = wire_bytes[..2].try_into().expect("два байта");
        let frame_len = recv
            .decode_length(length_field)
            .expect("разбирается")
            .expect("не терминатор");

        assert_eq!(wire_bytes.len(), 2 + frame_len.on_wire);
        let mut ciphertext = wire_bytes[2..2 + frame_len.ciphertext].to_vec();
        let plain = recv.open_chunk(&mut ciphertext).expect("совпадает");
        assert_eq!(plain, b"payload");
    }

    #[test]
    fn aes_gcm_round_trips() {
        round_trip(Wire::Aes128Gcm);
    }

    #[test]
    fn chacha_round_trips() {
        round_trip(Wire::Chacha20Poly1305);
    }

    #[test]
    fn none_round_trips_without_a_tag() {
        round_trip(Wire::None);
    }

    #[test]
    fn a_terminator_is_recognised_by_its_length() {
        let (mut send, mut recv) = pair(Wire::Aes128Gcm);
        let wire_bytes = seal_to_vec(&mut send, b"");
        let length_field: [u8; 2] = wire_bytes[..2].try_into().expect("два байта");
        assert_eq!(recv.decode_length(length_field).expect("разбирается"), None);
    }

    #[test]
    fn the_length_on_the_wire_is_not_the_real_length() {
        let (mut send, _recv) = pair(Wire::Aes128Gcm);
        let wire_bytes = seal_to_vec(&mut send, b"payload");
        let raw = u16::from_be_bytes(wire_bytes[..2].try_into().expect("два байта"));
        assert_ne!(usize::from(raw), b"payload".len() + 16);
    }

    #[test]
    fn two_chunks_use_different_nonces() {
        let (mut send, _recv) = pair(Wire::Aes128Gcm);
        let first = seal_to_vec(&mut send, b"same");
        let second = seal_to_vec(&mut send, b"same");
        assert_ne!(first, second);
    }
}
