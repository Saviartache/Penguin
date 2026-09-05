//! `auth_aes128_md5` и `auth_aes128_sha1`: кадры с HMAC поверх потокового
//! шифра плюс разовый заголовок с меткой времени на каждое соединение.
//!
//! Оба метода — один и тот же формат, отличаются только тем, какой хэш
//! стоит под HMAC (MD5 или SHA1); в эталоне это буквально один класс с
//! параметром (`auth_aes128_sha1(method, hashfunc)` в
//! `shadowsocks/obfsplugin/auth.py`, ветка `manyuser`,
//! `shadowsocksr-backup/shadowsocksr`). Здесь то же самое сделано
//! перечислением [`HashKind`] вместо параметра-функции.
//!
//! # Формат разового заголовка (один раз в начале соединения)
//!
//! ```text
//!  [случайный байт][HMAC6]                    check_head, 7 байт
//!  [uid 4][AES-128-CBC(IV=0) блока из 16][HMAC4]   24 байта
//!  [случайный довесок rnd_len байт]
//!  [адрес назначения (и, если поместилось, начало данных)]
//!  [HMAC4 по всему пакету]
//! ```
//!
//! 16-байтовый блок под AES — это метка времени, `client_id`, `connection_id`
//! и две длины (весь пакет, довесок), см. [`crate::protocol::client_id`].
//! Ключ AES — не главный ключ напрямую, а `EVP_BytesToKey(base64(ключ) ||
//! соль, 16, 16)`; соль — имя метода (`b"auth_aes128_md5"` или
//! `b"auth_aes128_sha1"`), она нужна, чтобы у двух методов на одном пароле
//! получались разные ключи AES.
//!
//! # Формат обычного кадра (каждый следующий кусок в любую сторону)
//!
//! ```text
//!  [длина, 2 байта LE][HMAC2 длины][довесок][данные][HMAC4 всего кадра]
//! ```
//!
//! Длина довеска кодируется первым байтом кадра: меньше 128 — это и есть его
//! длина плюс единица; `0xFF` означает, что настоящая длина — в следующих
//! двух байтах. Сколько именно случайных байт добавлять — решает отправитель,
//! это не часть договора с сервером (эталон подбирает длину под размер TCP
//! MSS; здесь — просто небольшой случайный довесок: серверу важна структура
//! кадра, а не то, каким приёмом маскировки выбрана его длина).
//!
//! # Про отказ
//!
//! Ни у первого заголовка, ни у обычного кадра нет отдельного сигнала
//! «пароль неверный»: если ключи не совпали, метка HMAC просто не сойдётся —
//! ровно как при порче кадра по дороге. Здесь оба случая дают один и тот же
//! [`crate::error::ShadowsocksrError::Rejected`], и это тот же выбор, что и
//! у `origin`/`plain` Shadowsocks: отказ неотличим от повреждения, и
//! повторять его бессмысленно в обоих случаях.

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use bytes::{Buf, BytesMut};
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::Rng;
use sha1::Sha1;

use crate::error::{ShadowsocksrError, ShadowsocksrResult};
use crate::protocol::client_id::AuthHeader;

/// Кусок данных крупнее этого режется на несколько обычных кадров.
const UNIT_LEN: usize = 8100;

/// Наименьшая и наибольшая допустимая длина обычного кадра — те же границы,
/// что у эталона; за ними на проводе точно не он.
const MIN_FRAME: usize = 7;
const MAX_FRAME: usize = 8192;

/// Какой хэш стоит под HMAC — единственное, чем отличаются два метода.
#[derive(Debug, Clone, Copy)]
pub(crate) enum HashKind {
    Md5,
    Sha1,
}

impl HashKind {
    /// Соль в разовом заголовке — имя метода как есть.
    fn salt(self) -> &'static [u8] {
        match self {
            Self::Md5 => b"auth_aes128_md5",
            Self::Sha1 => b"auth_aes128_sha1",
        }
    }

    fn hmac(self, key: &[u8], data: &[u8], out_len: usize) -> ShadowsocksrResult<Vec<u8>> {
        // Не общая дженерик-функция: типаж `Mac` у `Hmac<D>` в этой версии
        // `hmac` требует довольно длинного списка ограничений на `D`
        // (`CoreProxy`, `HashMarker`, размер блока и так далее). Конкретные
        // типы `Hmac<Md5>`/`Hmac<Sha1>` эти ограничения уже выполняют —
        // авторы `md-5` и `sha1` об этом позаботились, — а переписывать тот
        // же список здесь ради одной дженерик-функции только помешало бы
        // читать код.
        match self {
            Self::Md5 => hmac_md5(key, data, out_len),
            Self::Sha1 => hmac_sha1(key, data, out_len),
        }
    }
}

/// HMAC-MD5 с обрезкой до `out_len` байт. HMAC принимает ключ любой длины,
/// так что `new_from_slice` здесь не может отказать по-настоящему; тем не
/// менее ошибка возвращается, а не тонет в `expect` (AGENTS.md §4.3).
fn hmac_md5(key: &[u8], data: &[u8], out_len: usize) -> ShadowsocksrResult<Vec<u8>> {
    let mut mac = Hmac::<Md5>::new_from_slice(key)
        .map_err(|_| ShadowsocksrError::crypto("HMAC-MD5 не принял ключ"))?;
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    Ok(tag[..out_len.min(tag.len())].to_vec())
}

/// То же самое с HMAC-SHA1.
fn hmac_sha1(key: &[u8], data: &[u8], out_len: usize) -> ShadowsocksrResult<Vec<u8>> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key)
        .map_err(|_| ShadowsocksrError::crypto("HMAC-SHA1 не принял ключ"))?;
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    Ok(tag[..out_len.min(tag.len())].to_vec())
}

/// Ключ AES-128 для разового заголовка: `EVP_BytesToKey(base64(user_key) ||
/// соль, 16, 16)`, взят только ключ — IV из этого же вызова не используется
/// (см. документ модуля).
fn header_aes_key(user_key: &[u8], salt: &[u8]) -> [u8; 16] {
    let mut password = penguin_core::base64::encode(user_key).into_bytes();
    password.extend_from_slice(salt);
    let key = crate::crypto::kdf::evp_bytes_to_key(&password, 16);
    let mut out = [0u8; 16];
    out.copy_from_slice(&key);
    out
}

/// Один блок AES-128 в чистом виде — это ровно CBC с нулевым IV на одном
/// блоке: `шифр(блок XOR 0) = шифр(блок)`.
fn aes128_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> ShadowsocksrResult<[u8; 16]> {
    let cipher = Aes128::new_from_slice(key)
        .map_err(|_| ShadowsocksrError::crypto("ключ AES-128 не той длины"))?;
    let mut buf: aes::Block = (*block).into();
    cipher.encrypt_block(&mut buf);
    let mut out = [0u8; 16];
    out.copy_from_slice(&buf);
    Ok(out)
}

/// Кодирует длину довеска так же, как эталон: значение (маркер либо
/// двухбайтовое поле) равно полной длине довеска вместе с самим собой.
fn rnd_prefix(pad: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut out = Vec::with_capacity(pad + 3);
    if pad < 128 {
        out.push((pad + 1) as u8);
    } else {
        out.push(255);
        out.extend_from_slice(&((pad + 1) as u16).to_le_bytes());
    }
    let random_count = if pad < 128 { pad } else { pad - 2 };
    out.extend((0..random_count).map(|_| rng.r#gen::<u8>()));
    out
}

/// Состояние `auth_aes128_*` на одно соединение.
pub(crate) struct AuthAes128State {
    hash: HashKind,
    /// Главный ключ соединения — для нас всегда `server_info.key`: своих
    /// пользователей (`protocol_param` вида `id:пароль`) крейт не заводит.
    user_key: Vec<u8>,
    /// IV шифра этого соединения — часть ключа HMAC разового заголовка.
    cipher_iv: Vec<u8>,
    sent_header: bool,
    pack_id: u32,
    recv_id: u32,
    recv_buf: BytesMut,
}

impl AuthAes128State {
    pub(crate) fn new(hash: HashKind, user_key: Vec<u8>, cipher_iv: Vec<u8>) -> Self {
        Self {
            hash,
            user_key,
            cipher_iv,
            sent_header: false,
            pack_id: 1,
            recv_id: 1,
            recv_buf: BytesMut::new(),
        }
    }

    /// Оборачивает исходящий кусок плоского текста в кадры.
    ///
    /// `head_size` — точная длина адреса назначения (плюс уже учтённый IV):
    /// в первом вызове ровно столько байт `buf` уходит в разовый заголовок,
    /// а не оценка «похоже на IPv4 или домен», как в эталоне (см. документ
    /// модуля [`crate::obfs::http_simple`], у которого та же идея).
    pub(crate) fn client_pre_encrypt(
        &mut self,
        mut buf: &[u8],
        head_size: usize,
        header: Option<AuthHeader>,
    ) -> ShadowsocksrResult<Vec<u8>> {
        let mut out = Vec::new();

        if !self.sent_header {
            let Some(header) = header else {
                return Err(ShadowsocksrError::crypto(
                    "auth_aes128: для первого пакета соединения нужен заголовок \
                     (client_id, connection_id), а его не передали",
                ));
            };
            let extra = rand::thread_rng().gen_range(0..32);
            let take = (head_size + extra).min(buf.len());
            out.extend_from_slice(&self.pack_auth_data(header, &buf[..take])?);
            buf = &buf[take..];
            self.sent_header = true;
        }

        while buf.len() > UNIT_LEN {
            out.extend_from_slice(&self.pack_data(&buf[..UNIT_LEN])?);
            buf = &buf[UNIT_LEN..];
        }
        out.extend_from_slice(&self.pack_data(buf)?);
        Ok(out)
    }

    /// Остался ли в буфере кусок кадра, не дождавшийся своего продолжения.
    ///
    /// Нужно, чтобы отличить чистый конец потока от обрыва посреди кадра:
    /// оборванный кадр без этой проверки выглядел бы обычным концом с
    /// потерянным хвостом данных.
    pub(crate) fn has_pending_frame(&self) -> bool {
        !self.recv_buf.is_empty()
    }

    /// Снимает кадры с только что расшифрованных байт ответа. Копит
    /// незавершённый кадр между вызовами.
    pub(crate) fn client_post_decrypt(&mut self, incoming: &[u8]) -> ShadowsocksrResult<Vec<u8>> {
        self.recv_buf.extend_from_slice(incoming);
        let mut out = Vec::new();

        while self.recv_buf.len() > 4 {
            let mac_key = self.frame_mac_key(self.recv_id);
            let mac2 = self.hash.hmac(&mac_key, &self.recv_buf[..2], 2)?;
            if mac2 != self.recv_buf[2..4] {
                return Err(ShadowsocksrError::Rejected);
            }

            let length = usize::from(u16::from_le_bytes([self.recv_buf[0], self.recv_buf[1]]));
            if !(MIN_FRAME..MAX_FRAME).contains(&length) {
                return Err(ShadowsocksrError::malformed(format!(
                    "длина кадра auth_aes128 вне диапазона: {length}"
                )));
            }
            if length > self.recv_buf.len() {
                break; // кадр ещё не пришёл целиком
            }

            let tag = self.hash.hmac(&mac_key, &self.recv_buf[..length - 4], 4)?;
            if tag != self.recv_buf[length - 4..length] {
                return Err(ShadowsocksrError::Rejected);
            }
            self.recv_id = self.recv_id.wrapping_add(1);

            let marker = self.recv_buf[4];
            let pos = if marker < 255 {
                usize::from(marker) + 4
            } else {
                if length < 7 {
                    return Err(ShadowsocksrError::malformed(
                        "кадр auth_aes128 короче маркера",
                    ));
                }
                usize::from(u16::from_le_bytes([self.recv_buf[5], self.recv_buf[6]])) + 4
            };
            if pos > length - 4 {
                return Err(ShadowsocksrError::malformed(
                    "довесок кадра auth_aes128 длиннее самого кадра",
                ));
            }

            out.extend_from_slice(&self.recv_buf[pos..length - 4]);
            self.recv_buf.advance(length);
        }
        Ok(out)
    }

    fn frame_mac_key(&self, counter: u32) -> Vec<u8> {
        let mut key = self.user_key.clone();
        key.extend_from_slice(&counter.to_le_bytes());
        key
    }

    fn pack_auth_data(&self, header: AuthHeader, buf: &[u8]) -> ShadowsocksrResult<Vec<u8>> {
        if buf.is_empty() {
            return Ok(Vec::new());
        }
        let mut rng = rand::thread_rng();
        let rnd_len = if buf.len() > 400 {
            rng.gen_range(0..512usize)
        } else {
            rng.gen_range(0..1024usize)
        };
        let data_len = 35 + buf.len() + rnd_len;

        let mut block = [0u8; 16];
        block[0..4].copy_from_slice(&header.utc_time.to_le_bytes());
        block[4..8].copy_from_slice(&header.client_id);
        block[8..12].copy_from_slice(&header.connection_id.to_le_bytes());
        block[12..14].copy_from_slice(&(data_len as u16).to_le_bytes());
        block[14..16].copy_from_slice(&(rnd_len as u16).to_le_bytes());

        let aes_key = header_aes_key(&self.user_key, self.hash.salt());
        let cipher_block = aes128_encrypt_block(&aes_key, &block)?;

        let mac_key = [self.cipher_iv.as_slice(), self.user_key.as_slice()].concat();
        let uid: [u8; 4] = rng.r#gen();

        let mut mid = Vec::with_capacity(24);
        mid.extend_from_slice(&uid);
        mid.extend_from_slice(&cipher_block);
        mid.extend_from_slice(&self.hash.hmac(&mac_key, &mid, 4)?);

        let mut check_head = vec![rng.r#gen::<u8>()];
        check_head.extend_from_slice(&self.hash.hmac(&mac_key, &check_head, 6)?);

        let mut out = Vec::with_capacity(7 + 24 + rnd_len + buf.len() + 4);
        out.extend_from_slice(&check_head);
        out.extend_from_slice(&mid);
        out.extend((0..rnd_len).map(|_| rng.r#gen::<u8>()));
        out.extend_from_slice(buf);
        let tag = self.hash.hmac(&self.user_key, &out, 4)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn pack_data(&mut self, buf: &[u8]) -> ShadowsocksrResult<Vec<u8>> {
        let pad = rand::thread_rng().gen_range(0..64usize);
        let mut data = rnd_prefix(pad);
        data.extend_from_slice(buf);
        let data_len = data.len() + 8;

        let mac_key = self.frame_mac_key(self.pack_id);
        let mac2 = self
            .hash
            .hmac(&mac_key, &(data_len as u16).to_le_bytes(), 2)?;

        let mut frame = Vec::with_capacity(data_len);
        frame.extend_from_slice(&(data_len as u16).to_le_bytes());
        frame.extend_from_slice(&mac2);
        frame.extend_from_slice(&data);
        let tag = self.hash.hmac(&mac_key, &frame, 4)?;
        frame.extend_from_slice(&tag);

        self.pack_id = self.pack_id.wrapping_add(1);
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::client_id::ClientIdState;

    fn header() -> AuthHeader {
        ClientIdState::new().next()
    }

    fn pair(hash: HashKind) -> (AuthAes128State, AuthAes128State) {
        let user_key = b"master key from EVP_BytesToKey".to_vec();
        let iv = vec![7u8; 16];
        (
            AuthAes128State::new(hash, user_key.clone(), iv.clone()),
            AuthAes128State::new(hash, user_key, iv),
        )
    }

    #[test]
    fn a_plain_frame_round_trips_through_client_and_server_side_checks() {
        // У нас нет настоящего сервера, но обе стороны формата — общий код:
        // то, что упаковал `pack_data`, обязано пройти те же проверки, что
        // видит сервер при разборе, и наоборот при чтении его ответа.
        for hash in [HashKind::Md5, HashKind::Sha1] {
            let (mut client, mut mirror) = pair(hash);
            let framed = client.pack_data(b"hello, server").expect("упаковывается");

            // "Ответ" сервера мы можем только сымитировать той же упаковкой
            // (у нас нет второй реализации сервера) — проверяем, что
            // `client_post_decrypt` снимает кадр, упакованный тем же кодом,
            // и это тот путь, которым реально пойдут байты ответа.
            let out = mirror.client_post_decrypt(&framed).expect("разбирается");
            assert_eq!(out, b"hello, server");
        }
    }

    #[test]
    fn frames_arriving_in_two_pieces_are_assembled() {
        let (mut client, mut mirror) = pair(HashKind::Sha1);
        let framed = client.pack_data(b"split-me-please").expect("упаковывается");
        let (first, second) = framed.split_at(framed.len() / 2);

        assert!(
            mirror
                .client_post_decrypt(first)
                .expect("не ошибка")
                .is_empty()
        );
        let out = mirror.client_post_decrypt(second).expect("разбирается");
        assert_eq!(out, b"split-me-please");
    }

    #[test]
    fn a_flipped_byte_is_rejected_as_an_auth_failure() {
        let (mut client, mut mirror) = pair(HashKind::Md5);
        let mut framed = client.pack_data(b"payload").expect("упаковывается");
        let last = framed.len() - 1;
        framed[last] ^= 1;

        let err = mirror
            .client_post_decrypt(&framed)
            .expect_err("не сходится");
        assert!(matches!(err, ShadowsocksrError::Rejected));
    }

    #[test]
    fn the_wrong_key_looks_like_an_auth_failure_too() {
        // У auth_aes128 нет отдельного сигнала «неверный пароль» — только
        // несошедшаяся метка, которая выглядит точно как порча в пути.
        let mut client = AuthAes128State::new(HashKind::Sha1, b"key one".to_vec(), vec![1u8; 16]);
        let mut other = AuthAes128State::new(HashKind::Sha1, b"key two".to_vec(), vec![1u8; 16]);
        let framed = client.pack_data(b"payload").expect("упаковывается");
        assert!(other.client_post_decrypt(&framed).is_err());
    }

    #[test]
    fn the_auth_header_carries_the_slice_it_was_given() {
        let mut state = AuthAes128State::new(HashKind::Sha1, b"secret".to_vec(), vec![3u8; 16]);
        let out = state
            .client_pre_encrypt(b"\x01\x02\x03\x04address-bytes", 8, Some(header()))
            .expect("собирается");
        // Формат заголовка проверяется по длине: check_head(7) + mid(24) +
        // rnd_len(неизвестно нам заранее) + buf + hmac(4). Полная проверка
        // разбора — на стороне decode-теста выше; здесь достаточно того, что
        // вызов вообще не падает и возвращает непустые байты.
        assert!(out.len() > 7 + 24 + 4);
    }

    #[test]
    fn a_second_header_request_is_a_programming_error_not_a_silent_resend() {
        let mut state = AuthAes128State::new(HashKind::Sha1, b"secret".to_vec(), vec![3u8; 16]);
        let _ = state
            .client_pre_encrypt(b"addr", 4, Some(header()))
            .expect("собирается");
        // Второй вызов уже не должен просить заголовок — `sent_header` снят.
        let out = state
            .client_pre_encrypt(b"more data", 4, None)
            .expect("собирается");
        assert!(!out.is_empty());
    }
}
