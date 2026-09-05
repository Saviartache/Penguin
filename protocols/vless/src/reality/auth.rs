//! Данные опознания Reality: то, что живёт в 32 байтах `SessionID` вместо
//! случайного значения обычного клиента, и подтверждение сервера.
//!
//! **Формат данных опознания и вывод `AuthKey` нельзя свести к
//! RFC** — Reality не стандарт, а конкретная реализация; всё ниже выписано
//! из `Xray-core` (`transport/internet/reality/reality.go`, функция
//! `UClient`, ревизия `cd4ce97`) и независимо сверено с `sing-box`
//! (`common/tls/reality_client.go`, `ClientHandshake`, тег `v1.12`-ветки
//! `testing`) — обе реализации совпадают байт в байт по формуле, но **ни
//! одного результата не с чем сверить без живого сервера**: опубликованных
//! тестовых векторов Reality не существует (в отличие от TLS 1.3 самого по
//! себе, для которого есть RFC 8448 — см. `key_schedule.rs`).
//!
//! ```text
//!            общий секрет X25519 с публичным ключом Reality
//!                              │
//!         HKDF-SHA256(salt=client_random[..20], info="REALITY")
//!                              │
//!                              ▼
//!                           AuthKey (32 байта)
//!                    │                        │
//!      AES-256-GCM(SessionID)          HMAC-SHA512(сертификат)
//!      seal_session_id (клиент)        verify_certificate (сервер → клиент)
//! ```

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{self, KeyType};
use ring::hmac;

use crate::reality::error::RealityError;

/// Версия клиента, которую Reality кладёт в первые три байта данных
/// опознания.
///
/// Настоящего значения у этой реализации нет — она не `Xray-core` и не
/// `sing-box`, и сверить номер не с чем. `sing-box`, тоже не будучи
/// `Xray-core`, в этом месте выдаёт себя за его версию `1.8.1`
/// (`reality_client.go`: `hello.SessionId[0] = 1; [1] = 8; [2] = 1`) — сервер
/// проверяет эти байты, только если в его настройках заданы
/// `minClientVer`/`maxClientVer` (`XTLS/reality`, `tls.go`, строки 257-258:
/// `config.MinClientVer == nil || ... ; config.MaxClientVer == nil || ...`),
/// а по умолчанию их нет. Тот же выбор здесь — не подтверждённый факт, а
/// совместимость по прецеденту одной чужой реализации. **Если сервер всё же
/// ограничивает версию строже, чем `1.8.1`, отличить это от «нас не узнали»
/// нельзя** — сервер в обоих случаях просто не отзовётся (`error.rs`,
/// [`crate::reality::error::RealityError::NotRecognized`]).
const CLIENT_VERSION: [u8; 3] = [1, 8, 1];

/// Длина данных опознания до шифрования: версия(3) + резерв(1) + время(4) +
/// `short_id`(8).
const PAYLOAD_LEN: usize = 16;

/// Данные опознания до шифрования.
///
/// `Xray-core`, тот же файл, строки 160-168:
/// ```text
/// hello.SessionId[0] = core.Version_x
/// hello.SessionId[1] = core.Version_y
/// hello.SessionId[2] = core.Version_z
/// hello.SessionId[3] = 0 // reserved
/// binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
/// copy(hello.SessionId[8:], config.ShortId)
/// ```
/// `sing-box` кладёт те же поля в том же порядке (`reality_client.go`,
/// строки после `hello.SessionId = make([]byte, 32)`).
fn payload(short_id: [u8; 8], unix_time: u32) -> [u8; PAYLOAD_LEN] {
    let mut out = [0u8; PAYLOAD_LEN];
    out[0..3].copy_from_slice(&CLIENT_VERSION);
    out[3] = 0; // резерв
    out[4..8].copy_from_slice(&unix_time.to_be_bytes());
    out[8..16].copy_from_slice(&short_id);
    out
}

struct AuthKeyLen;

impl KeyType for AuthKeyLen {
    fn len(&self) -> usize {
        32
    }
}

/// Выводит `AuthKey` — общий ключ Reality — из общего секрета X25519 с
/// публичным ключом сервера.
///
/// `HKDF-SHA256(salt = client_random[..20], ikm = shared_secret, info =
/// "REALITY", L = 32)`. `Xray-core`, тот же файл, строка 176:
/// `hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20],
/// []byte("REALITY")).Read(uConn.AuthKey)` — сигнатура `hkdf.New` в
/// `golang.org/x/crypto/hkdf` это `(hash, secret, salt, info)`, то есть
/// `uConn.AuthKey` (общий секрет на входе) — это `secret`/`IKM`, а
/// `hello.Random[:20]` — именно `salt`, не `info`. Сервер вычисляет то же
/// самое над своей стороной общего секрета (`XTLS/reality`, `tls.go`, строка
/// 233: `hkdf.New(sha256.New, hs.c.AuthKey, hs.clientHello.random[:20],
/// []byte("REALITY"))`) — независимое подтверждение того же порядка
/// аргументов с другой стороны протокола.
///
/// Результат используется дважды: шифрует `SessionID`
/// ([`seal_session_id`]) и заверяет сертификат сервера
/// ([`verify_certificate`]) — Reality не разделяет эти ключи.
pub fn derive_auth_key(
    shared_secret: &[u8; 32],
    client_random: &[u8; 32],
) -> Result<[u8; 32], RealityError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &client_random[..20]);
    let prk = salt.extract(shared_secret);
    // `Okm` заимствует у `info` — временный массив с одним элементом не
    // пережил бы выражение, поэтому у него есть имя.
    let info: [&[u8]; 1] = [b"REALITY"];
    let okm = prk
        .expand(&info, AuthKeyLen)
        .map_err(|_| RealityError::KeySchedule)?;
    let mut out = [0u8; 32];
    okm.fill(&mut out).map_err(|_| RealityError::KeySchedule)?;
    Ok(out)
}

/// Шифрует данные опознания в 32 байта `SessionID`.
///
/// `AES-256-GCM(key=auth_key, nonce=client_random[20..32],
/// plaintext=payload, aad=ClientHello с ещё нулевым SessionID)`. `Xray-core`,
/// тот же файл, строка 178: `aead.Seal(hello.SessionId[:0],
/// hello.Random[20:], hello.SessionId[:16], hello.Raw)`. `dst =
/// hello.SessionId[:0]` в Go — «писать с начала этого среза», а не «нулевой
/// длины навсегда»: `Seal` дописывает к `dst` результат, 16 байт шифротекста
/// вместе с 16 байтами метки GCM, ровно длину `SessionID`. `hello.Raw` в
/// момент вызова — это `ClientHello` целиком с ещё нулевым `SessionID`: он
/// зашит в AAD раньше, чем подменяется зашифрованным значением (см.
/// [`penguin_utls::ClientHello::patch_session_id`], откуда и взят этот
/// порядок операций).
pub fn seal_session_id(
    auth_key: &[u8; 32],
    client_random: &[u8; 32],
    short_id: [u8; 8],
    unix_time: u32,
    client_hello_with_zero_session_id: &[u8],
) -> Result<[u8; 32], RealityError> {
    let plaintext = payload(short_id, unix_time);

    let unbound = UnboundKey::new(&aead::AES_256_GCM, auth_key)
        .map_err(|_| RealityError::Crypto("ключ AES-256-GCM"))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&client_random[20..32])
        .map_err(|_| RealityError::Crypto("нонс AES-256-GCM"))?;

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        nonce,
        Aad::from(client_hello_with_zero_session_id),
        &mut in_out,
    )
    .map_err(|_| RealityError::Crypto("шифрование SessionID"))?;

    let mut out = [0u8; 32];
    out.copy_from_slice(&in_out);
    Ok(out)
}

/// Подтверждение сервера: сертификат настоящий, только если
/// `HMAC-SHA512(AuthKey, subjectPublicKey) == signatureValue`.
///
/// `Xray-core`, `reality.go`, `UConn.VerifyPeerCertificate`:
/// `h := hmac.New(sha512.New, c.AuthKey); h.Write(pub);
/// bytes.Equal(h.Sum(nil), certs[0].Signature)`. Независимо повторено
/// `sing-box` (`reality_client.go`, `realityVerifier.VerifyPeerCertificate`)
/// — тот же ключ (`AuthKey` после `HKDF`, не общий секрет напрямую), тот же
/// хеш, тот же порядок аргументов HMAC.
///
/// Сравнение здесь — [`ring::hmac::verify`], постоянного времени; в обоих
/// эталонах оно обычное (`bytes.Equal` в Go не защищён от атак по времени),
/// но заменить его без изменения формата ничего не стоит, и опускать эту
/// разницу незачем.
pub fn verify_certificate(
    auth_key: &[u8; 32],
    ed25519_public_key: &[u8; 32],
    signature: &[u8],
) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    hmac::verify(&key, ed25519_public_key, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_layout_matches_the_documented_field_order() {
        let short_id = [0xAA; 8];
        let bytes = payload(short_id, 0x0102_0304);
        assert_eq!(&bytes[0..3], &CLIENT_VERSION);
        assert_eq!(bytes[3], 0, "резерв всегда нулевой");
        assert_eq!(&bytes[4..8], &0x0102_0304u32.to_be_bytes());
        assert_eq!(&bytes[8..16], &short_id);
    }

    #[test]
    fn deriving_the_auth_key_is_deterministic() {
        let secret = [7u8; 32];
        let random = [3u8; 32];
        let first = derive_auth_key(&secret, &random).expect("считается");
        let second = derive_auth_key(&secret, &random).expect("считается");
        assert_eq!(first, second);
    }

    #[test]
    fn a_different_client_random_changes_the_auth_key() {
        // client_random входит в HKDF как соль — это не круговой тест
        // формата (мы не знаем, тот ли это `salt`, что ждёт сервер), а
        // проверка, что параметр вообще на что-то влияет, а не
        // проигнорирован по опечатке.
        let secret = [7u8; 32];
        let a = derive_auth_key(&secret, &[1; 32]).expect("считается");
        let b = derive_auth_key(&secret, &[2; 32]).expect("считается");
        assert_ne!(a, b);
    }

    /// Круговой тест: зашифровали — расшифровали тем же AEAD напрямую через
    /// `ring`, в обход `seal_session_id`. Ловит опечатку в порядке
    /// ключ/нонс/AAD, но НЕ доказывает, что формат совпадает с тем, что
    /// ждёт настоящий сервер Reality, — этого без живого сервера не
    /// проверить (см. документ модуля).
    #[test]
    fn sealing_the_session_id_round_trips_under_the_same_aead() {
        let auth_key = [9u8; 32];
        let client_random = [5u8; 32];
        let short_id = [0x11; 8];
        let unix_time = 1_700_000_000u32;
        let hello_with_zero_session_id = "клиентское приветствие с нулевым SessionID".as_bytes();
        let sealed = seal_session_id(
            &auth_key,
            &client_random,
            short_id,
            unix_time,
            hello_with_zero_session_id,
        )
        .expect("шифруется");
        assert_eq!(sealed.len(), 32);

        let unbound = UnboundKey::new(&aead::AES_256_GCM, &auth_key).expect("ключ верен");
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&client_random[20..32]).expect("нонс верен");
        let mut in_out = sealed.to_vec();
        let opened = key
            .open_in_place(nonce, Aad::from(hello_with_zero_session_id), &mut in_out)
            .expect("расшифровывается тем же ключом");

        assert_eq!(opened, &payload(short_id, unix_time));
    }

    #[test]
    fn tampering_with_the_aad_breaks_decryption() {
        // AAD — это ClientHello целиком: если хотя бы один байт после
        // подписания изменится (например, кто-то на пути подменил
        // расширение), GCM обязан отказать, а не расшифровать молча.
        let auth_key = [9u8; 32];
        let client_random = [5u8; 32];
        let sealed =
            seal_session_id(&auth_key, &client_random, [0; 8], 0, b"hello-v1").expect("шифруется");

        let unbound = UnboundKey::new(&aead::AES_256_GCM, &auth_key).expect("ключ верен");
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&client_random[20..32]).expect("нонс верен");
        let mut in_out = sealed.to_vec();
        assert!(
            key.open_in_place(nonce, Aad::from(b"hello-v2".as_ref()), &mut in_out)
                .is_err()
        );
    }

    /// RFC 4231 §4.2 ("Test Case 1" для HMAC-SHA-512) — независимый от
    /// Reality вектор: проверяет только то, что `ring::hmac::verify` в этой
    /// обвязке действительно считает HMAC-SHA-512 так, как определяет RFC, а
    /// не что-то похожее на него. Ключ и данные — из RFC, не наши.
    #[test]
    fn hmac_sha512_matches_the_rfc_4231_test_vector() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected: [u8; 64] = [
            0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d,
            0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05,
            0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b,
            0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
            0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54,
        ];
        let mac_key = hmac::Key::new(hmac::HMAC_SHA512, &key);
        assert!(hmac::verify(&mac_key, data, &expected).is_ok());
    }

    #[test]
    fn verify_certificate_uses_the_same_hmac_wiring() {
        let auth_key = [0x0b; 32];
        let pubkey = [0xAB; 32];
        let key = hmac::Key::new(hmac::HMAC_SHA512, &auth_key);
        let tag = hmac::sign(&key, &pubkey);
        assert!(verify_certificate(&auth_key, &pubkey, tag.as_ref()));

        let mut wrong = tag.as_ref().to_vec();
        wrong[0] ^= 1;
        assert!(!verify_certificate(&auth_key, &pubkey, &wrong));
    }
}
