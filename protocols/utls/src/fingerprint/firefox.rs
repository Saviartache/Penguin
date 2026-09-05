//! Firefox 120 (ноябрь 2023, `HelloFirefox_120` в uTLS, `u_parrots.go` на
//! ревизии `23b1dac`).
//!
//! # Ни GREASE, ни перемешивания
//!
//! GREASE (RFC 8701) — придумка BoringSSL, а у Firefox своя криптобиблиотека,
//! NSS, которая её не реализует вовсе. Список шифров, кривых и версий у
//! Firefox настоящий целиком, без единой пустышки, а порядок расширений
//! фиксирован и не меняется от соединения к соединению — то, что делает
//! Chrome с версии 106, у Firefox не появилось. Отсутствие GREASE — тоже
//! часть отпечатка: клиент, назвавшийся Firefox, но вставивший хоть одно
//! значение `0x?A?A`, был бы виден с одного пакета.
//!
//! Единственное исключение с виду похоже на GREASE, но им не является:
//! `encrypted_client_hello` в варианте «тревога» определён самим черновиком
//! ECH (draft-ietf-tls-esni), а не BoringSSL, и его посылают все, кто
//! поддержал черновик, включая NSS.
//!
//! # Два настоящих ключа в `key_share`
//!
//! Firefox предлагает не одну группу, а две — `X25519` и `P-256` — с
//! настоящими точками у обеих. Если сервер (или сайт, которому Reality
//! перешлёт `ClientHello` вхолостую) выберет вторую, рукопожатие всё ещё
//! можно довершить: `crate::key_exchange::generate_p256` тоже отдаёт
//! пригодный закрытый ключ, не только байты для вида.
//!
//! # Расширения без формы generic-кодировщиков
//!
//! `delegated_credentials` (34) и `record_size_limit` (28) у Firefox —
//! черновики без общепринятого номера ("fake" в терминах uTLS: код есть,
//! реализация неполная и у клиента, и часто у сервера). Первый по форме
//! совпадает с `signature_algorithms` — список идентичный, отличается только
//! код расширения, поэтому переиспользован тот же `generic::u16_list_u16_len`.
//!
//! Сверка: строка JA3, найденная поиском и подписанная «Firefox 120», не
//! совпала с набором расширений и шифров из этого файла (в ней есть `padding`
//! и ALPS, которых у Firefox не бывает, и шифры DHE, которых нет ни в одной
//! версии Firefox из uTLS) — это чужой или ошибочно подписанный пример, а не
//! настоящий захват. Доверять ему нельзя, и в решении он не участвовал:
//! список ниже сверен только с исходником uTLS.

use rand::RngCore;

use crate::client_hello::ExtensionSlot;
use crate::error::UtlsResult;
use crate::extension::{ech_grease, fixed, generic, sni};
use crate::key_exchange::{self, KeyExchange};

/// Шифры, точно в этом порядке. GREASE среди них нет ни одного — см. текст
/// модуля.
pub const CIPHER_SUITES: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
    0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
    0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
    0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
];

/// Единственный метод сжатия — TLS 1.3 запрещает любой, кроме этого, но поле
/// осталось от совместимости и должно быть заполнено.
pub const COMPRESSION_METHODS: &[u8] = &[0];

const CURVE_X25519: u16 = 29;
const CURVE_P256: u16 = 23;
const CURVE_P384: u16 = 24;
const CURVE_P521: u16 = 25;
/// `ffdhe2048` (RFC 7919, §3) — Firefox называет и конечно-полевые группы,
/// хотя ключ по ним не строит ни при каких настройках по умолчанию.
const GROUP_FFDHE2048: u16 = 0x0100;
/// `ffdhe3072`.
const GROUP_FFDHE3072: u16 = 0x0101;

/// Единственная длина открытого текста, которую предлагает GREASE ECH у
/// Firefox, — в отличие от Chrome, у которого их четыре на выбор.
const ECH_GREASE_PAYLOAD_LENS: &[u16] = &[223];

/// В отличие от Chrome (`BoringGREASEECH()`), у Firefox два кандидата AEAD:
/// сервер должен быть готов увидеть оба, и на разных соединениях увидит.
const ECH_GREASE_AEADS: &[u16] = &[
    ech_grease::AEAD_AES_128_GCM,
    ech_grease::AEAD_CHACHA20_POLY1305,
];

/// Собирает расширения и запрашивает пары ключей `X25519` и `P-256`.
pub(crate) fn build(
    rng: &mut impl RngCore,
    host: &str,
) -> UtlsResult<(Vec<ExtensionSlot>, Vec<KeyExchange>)> {
    let system_rng = ring::rand::SystemRandom::new();
    let x25519 = key_exchange::generate_x25519(&system_rng)?;
    let p256 = key_exchange::generate_p256(&system_rng)?;

    // Ни одно расширение здесь не якорь: Firefox не перемешивает порядок,
    // и вся эта разметка нужна только для того, чтобы делить один и тот же
    // тип слота с Chrome в общей сборке (`crate::client_hello::assemble`).
    let fixed_slot = |bytes: Vec<u8>| ExtensionSlot {
        bytes,
        anchored: true,
    };

    let extensions = vec![
        fixed_slot(sni::encode(host)),
        fixed_slot(generic::empty(23)), // extended_master_secret
        fixed_slot(fixed::renegotiation_info()),
        fixed_slot(generic::u16_list_u16_len(
            10, // supported_groups
            &[
                CURVE_X25519,
                CURVE_P256,
                CURVE_P384,
                CURVE_P521,
                GROUP_FFDHE2048,
                GROUP_FFDHE3072,
            ],
        )),
        fixed_slot(generic::u8_list(11, &[0])), // ec_point_formats
        fixed_slot(generic::empty(35)),         // session_ticket
        fixed_slot(generic::string_list(
            16,
            &[
                penguin_transport::tls::ALPN_H2,
                penguin_transport::tls::ALPN_HTTP11,
            ],
        )),
        fixed_slot(fixed::status_request()),
        fixed_slot(generic::u16_list_u16_len(
            34, // delegated_credentials (черновик, "fake" в терминах uTLS)
            &[
                0x0403, // ecdsa_secp256r1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0603, // ecdsa_secp521r1_sha512
                0x0203, // ecdsa_sha1
            ],
        )),
        fixed_slot(crate::extension::key_share::encode(&[
            crate::extension::key_share::Entry {
                group: CURVE_X25519,
                data: &x25519.public,
            },
            crate::extension::key_share::Entry {
                group: CURVE_P256,
                data: &p256.public,
            },
        ])),
        fixed_slot(generic::u16_list_u8_len(
            43, // supported_versions — без GREASE, см. текст модуля
            &[0x0304, 0x0303],
        )),
        fixed_slot(generic::u16_list_u16_len(
            13, // signature_algorithms
            &[
                0x0403, // ecdsa_secp256r1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0603, // ecdsa_secp521r1_sha512
                0x0804, // rsa_pss_rsae_sha256
                0x0805, // rsa_pss_rsae_sha384
                0x0806, // rsa_pss_rsae_sha512
                0x0401, // rsa_pkcs1_sha256
                0x0501, // rsa_pkcs1_sha384
                0x0601, // rsa_pkcs1_sha512
                0x0203, // ecdsa_sha1
                0x0201, // rsa_pkcs1_sha1
            ],
        )),
        fixed_slot(generic::u8_list(45, &[1])), // psk_key_exchange_modes
        fixed_slot(fixed::record_size_limit(0x4001)),
        fixed_slot(ech_grease::encode(
            rng,
            ECH_GREASE_AEADS,
            ECH_GREASE_PAYLOAD_LENS,
        )),
    ];

    Ok((extensions, vec![x25519, p256]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cipher_or_extension_is_grease() {
        let mut rng = rand::rngs::mock::StepRng::new(1, 1);
        for cipher in CIPHER_SUITES {
            assert!(!crate::grease::is_grease(*cipher));
        }
        let (extensions, keys) = build(&mut rng, "example.com").expect("собирается");
        assert!(extensions.iter().all(|e| e.anchored), "порядок не меняется");
        assert_eq!(keys.len(), 2, "Firefox предлагает X25519 и P-256");
    }

    #[test]
    fn the_second_key_is_a_real_p256_point() {
        let mut rng = rand::rngs::mock::StepRng::new(9, 3);
        let (_, keys) = build(&mut rng, "example.com").expect("собирается");
        assert_eq!(keys[0].public.len(), 32, "первый ключ — X25519");
        assert_eq!(keys[1].public.len(), 65, "второй — несжатая точка P-256");
    }
}
