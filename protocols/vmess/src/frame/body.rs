//! Кадр тела: длина (может быть замаскирована), кусок, может быть с меткой,
//! может быть с дополнением.
//!
//! ```text
//! ──► [длина, 2 байта, может ⊕ маска] [кусок + метка AEAD, если есть] [дополнение, если есть] ...
//! ```
//!
//! # Маскировка длины (`0x04`)
//!
//! Длина — не сама по себе, а результат `длина ⊕ следующее слово потока
//! Shake128`, засеянного целиком шестнадцатибайтовым `IV` тела. Это отдельный
//! кеystream от AEAD: даже у `security = "none"`, где кусок не шифруется и не
//! заверяется вовсе, длина всё равно маскируется — `RequestOptionChunkMasking`
//! стоит и там (`proxy/vmess/outbound/outbound.go`, эталон
//! `v2fly/v2ray-core`, `master`).
//!
//! # Нонс куска (только у AES-128-GCM и ChaCha20-Poly1305)
//!
//! `counter (2 байта, big-endian) || IV[2..12]` — двенадцать байт, где
//! меняется только счётчик, начинающийся с нуля и растущий на каждый кусок.
//! Байты `IV[12..16]` в нонсе не участвуют вовсе (`GenerateChunkNonce`,
//! `proxy/vmess/encoding/client.go`). У `none` и `zero` нонса нет: `none`
//! шифра не завершил, `zero` — не кадрован вовсе (см. [`crate::crypto::security`]).
//!
//! # Дополнение (`0x08`)
//!
//! Ещё одно слово того же потока Shake128, взятое **до** маскировки длины —
//! `NextPaddingLen() % 64` случайных байт, дописанных за меткой открытым
//! текстом. Только у AES-128-GCM и ChaCha20-Poly1305: `none` и `zero` его не
//! получают (см. [`crate::crypto::security::Wire::option_byte`]).
//!
//! # Терминатор
//!
//! Кусок с пустыми данными (длина кадра равна ровно метке плюс дополнение)
//! значит «дальше ничего не будет» — явный сигнал конца тела, а не совпадение
//! длины. Проверяется до попытки расшифровать, а не после.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::crypto::security::Wire;
use crate::error::{VmessError, VmessResult};

/// Наш собственный предел на кусок, который мы сами формируем при записи.
///
/// Не протокольная константа: длина кадра пишется двумя байтами, и потолок
/// у неё — `0xFFFF` минус метка (16) и наибольшее дополнение (63). Выбран
/// впритык к этому потолку, а не к удобному «покруглее», по одной причине:
/// у VMess одна отправка датаграммы ([`crate::datagram::VmessDatagram`],
/// `ProxyDatagram::send_to`) обязана
/// уйти ровно одним куском ([`BodyCipher::seal_chunk`]) — кусок сервер
/// пересылает как отдельный пакет UDP, и разрезать одну датаграмму на два
/// куска значит доставить два пакета там, где отправили один. Меньший
/// предел был бы неправ для датаграммы длиннее его самого; на TCP он же
/// просто определяет, как крупно резать поток, — здесь годится любой.
pub const MAX_PLAINTEXT: usize = 0xFFFF - 16 - 63;

/// Сколько байт кадра ждать после поля длины, и сколько из них — кусок.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkLength {
    /// Всего байт после поля длины: кусок, метка, дополнение.
    pub on_wire: usize,
    /// Из них — кусок с меткой, без дополнения. Ровно столько ждёт
    /// [`BodyCipher::open_chunk`].
    pub ciphertext: usize,
}

/// Шифр одного направления одного соединения.
pub struct BodyCipher {
    aead: Option<Aead>,
    mask: Shake128Xof,
    padded: bool,
    tag_len: usize,
}

/// AEAD-часть шифра — только у AES-128-GCM и ChaCha20-Poly1305.
struct Aead {
    key: LessSafeKey,
    iv_tail: [u8; 10],
    counter: u16,
}

impl BodyCipher {
    /// Строит шифр по уже приведённому шифру и ключу/`IV` тела этого
    /// направления (`request_body_*` на запись, `response_body_*` на чтение).
    ///
    /// `wire == Zero` сюда не доходит: у него нет ни кадра, ни этого типа —
    /// см. [`crate::stream`].
    pub fn new(wire: Wire, body_key: &[u8; 16], body_iv: &[u8; 16]) -> Self {
        let mut mask = Shake128::default();
        mask.update(body_iv);

        let aead = wire.ring_algorithm().map(|algorithm| {
            let key_bytes = wire.effective_key(body_key);
            // Длина ключа задана самим `Wire` и совпадает с алгоритмом по
            // построению — `ring` не может отказать здесь.
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

    /// Шифрует один кусок целиком: маскированная длина, кусок, метка,
    /// дополнение. Пустой `plain` — терминатор конца тела.
    pub fn seal_chunk(&mut self, plain: &[u8]) -> VmessResult<Vec<u8>> {
        let padding_len = self.next_padding_len();

        let sealed = match &mut self.aead {
            Some(aead) => {
                let mut buffer = plain.to_vec();
                let nonce = aead.next_nonce();
                aead.key
                    .seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer)
                    .map_err(|_| VmessError::malformed("кусок тела не зашифровался"))?;
                buffer
            }
            None => plain.to_vec(),
        };

        let declared_len = u16::try_from(sealed.len() + padding_len)
            .map_err(|_| VmessError::Oversized(sealed.len() + padding_len))?;

        let mut out = Vec::with_capacity(2 + sealed.len() + padding_len);
        out.extend_from_slice(&self.mask_length(declared_len).to_be_bytes());
        out.extend_from_slice(&sealed);
        if padding_len > 0 {
            let before = out.len();
            out.resize(before + padding_len, 0);
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut out[before..]);
        }
        Ok(out)
    }

    /// Разбирает уже снятое с провода поле длины (два байта до маскировки).
    ///
    /// `Ok(None)` — терминатор, дальше по потоку данных не будет.
    /// `Ok(Some(_))` называет, сколько байт кадра ждать следом
    /// ([`ChunkLength::on_wire`]) и сколько из них — кусок с меткой, без
    /// дополнения ([`ChunkLength::ciphertext`]) — именно столько отдаётся
    /// [`Self::open_chunk`], а не всё прочитанное целиком.
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

    /// Расшифровывает кусок на месте. `frame` — ровно
    /// [`ChunkLength::ciphertext`] байт: кусок и метка, без дополнения.
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

    /// Длина метки подлинности — ноль у `none`.
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

    fn mask_length(&mut self, declared: u16) -> u16 {
        declared ^ self.mask.next_u16()
    }
}

impl Aead {
    /// Нонс текущего куска и продвижение счётчика.
    fn next_nonce(&mut self) -> Nonce {
        let mut bytes = [0u8; 12];
        bytes[..2].copy_from_slice(&self.counter.to_be_bytes());
        bytes[2..].copy_from_slice(&self.iv_tail);
        self.counter = self.counter.wrapping_add(1);
        Nonce::assume_unique_for_key(bytes)
    }
}

/// Поток Shake128, отдающий по два байта за раз — вплотную к тому, как
/// эталон читает `ShakeSizeParser.next()`.
struct Shake128Xof(sha3::Shake128Reader);

impl Shake128Xof {
    fn next_u16(&mut self) -> u16 {
        let mut buffer = [0u8; 2];
        self.0.read(&mut buffer);
        u16::from_be_bytes(buffer)
    }
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
        let wire_bytes = send.seal_chunk(b"payload").expect("шифруется");

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
        let wire_bytes = send.seal_chunk(b"").expect("шифруется");
        let length_field: [u8; 2] = wire_bytes[..2].try_into().expect("два байта");
        assert_eq!(recv.decode_length(length_field).expect("разбирается"), None);
    }

    #[test]
    fn the_length_on_the_wire_is_not_the_real_length() {
        // Маскировка обязана хоть что-то менять, иначе это не маскировка.
        let (mut send, _recv) = pair(Wire::Aes128Gcm);
        let wire_bytes = send.seal_chunk(b"payload").expect("шифруется");
        let raw = u16::from_be_bytes(wire_bytes[..2].try_into().expect("два байта"));
        assert_ne!(usize::from(raw), b"payload".len() + 16);
    }

    #[test]
    fn two_chunks_use_different_nonces() {
        // Разный нонс — разный шифротекст на тех же данных.
        let (mut send, _recv) = pair(Wire::Aes128Gcm);
        let first = send.seal_chunk(b"same").expect("шифруется");
        let second = send.seal_chunk(b"same").expect("шифруется");
        assert_ne!(first, second);
    }
}
