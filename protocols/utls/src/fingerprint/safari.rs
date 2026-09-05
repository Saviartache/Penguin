//! Safari 16.0 (macOS/iOS, сентябрь 2022, `HelloSafari_16_0` в uTLS,
//! `u_parrots.go` на ревизии `23b1dac`).
//!
//! # BoringSSL под капотом, но не тот же порядок
//!
//! Safari, как и Chrome, построен на BoringSSL — отсюда GREASE (тот же набор
//! ролей: шифр, кривая, оба псевдорасширения, версия) и тот же `padding` по
//! `BoringPaddingStyle`. Но перемешивания расширений у Safari нет: список
//! идёт в одном и том же порядке каждый раз. И набор у него короче, чем у
//! Chrome, — ни `session_ticket`, ни ALPS, ни GREASE ECH: этих трёх
//! расширений у `HelloSafari_16_0` попросту нет в списке uTLS.
//!
//! # Повторяющаяся запись в `signature_algorithms` — не опечатка этого файла
//!
//! `PSSWithSHA384` (`0x0805`) в списке подписей встречается дважды подряд.
//! Это не ошибка переноса: в `u_parrots.go` она продублирована так же, и
//! раз задача — не выдумывать байт, а повторить эталон, дубликат остаётся.
//!
//! # Сжатие сертификата — Zlib, а не Brotli
//!
//! У Chrome в этом же расширении `CertCompressionBrotli`; у Safari —
//! `CertCompressionZlib`. Расхождение реальное, не опечатка: так записано в
//! обоих местах uTLS.
//!
//! Сверка: как и для Chrome 120, независимого захвата трафика для сверки
//! байт в байт не нашлось; список сверен только с исходником uTLS.

use rand::RngCore;

use crate::client_hello::ExtensionSlot;
use crate::error::UtlsResult;
use crate::extension::{fixed, generic, grease_placeholder, key_share, sni};
use crate::grease::GreaseValues;
use crate::key_exchange::{self, KeyExchange};

/// Шифры, точно в этом порядке. Первый — место GREASE.
pub const CIPHER_SUITES: &[u16] = &[
    crate::grease::PLACEHOLDER,
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
    0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
    0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
    0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
    0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
    0xc008, // FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    0xc012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
];

/// Единственный метод сжатия — TLS 1.3 запрещает любой, кроме этого, но поле
/// осталось от совместимости и должно быть заполнено.
pub const COMPRESSION_METHODS: &[u8] = &[0];

const CURVE_X25519: u16 = 29;
const CURVE_P256: u16 = 23;
const CURVE_P384: u16 = 24;
const CURVE_P521: u16 = 25;

/// Собирает расширения и запрашивает пару ключей `X25519` для `key_share`.
pub(crate) fn build(
    rng: &mut impl RngCore,
    host: &str,
) -> UtlsResult<(Vec<ExtensionSlot>, Vec<KeyExchange>)> {
    let grease = GreaseValues::from_rng(rng);
    let system_rng = ring::rand::SystemRandom::new();
    let x25519 = key_exchange::generate_x25519(&system_rng)?;

    // Порядок не перемешивается, но два GREASE-расширения всё равно якоря:
    // это тот самый смысл, что и у Chrome — сборка не должна пытаться
    // передвинуть их, если однажды у Safari тоже появится перемешивание.
    let fixed_slot = |bytes: Vec<u8>| ExtensionSlot {
        bytes,
        anchored: true,
    };

    let extensions = vec![
        fixed_slot(grease_placeholder(grease.extension_first, &[])),
        fixed_slot(sni::encode(host)),
        fixed_slot(generic::empty(23)), // extended_master_secret
        fixed_slot(fixed::renegotiation_info()),
        fixed_slot(generic::u16_list_u16_len(
            10, // supported_groups
            &[
                grease.group,
                CURVE_X25519,
                CURVE_P256,
                CURVE_P384,
                CURVE_P521,
            ],
        )),
        fixed_slot(generic::u8_list(11, &[0])), // ec_point_formats
        fixed_slot(generic::string_list(
            16, // alpn
            &[
                penguin_transport::tls::ALPN_H2,
                penguin_transport::tls::ALPN_HTTP11,
            ],
        )),
        fixed_slot(fixed::status_request()),
        fixed_slot(generic::u16_list_u16_len(
            13, // signature_algorithms — с повторной записью, см. текст модуля
            &[
                0x0403, // ecdsa_secp256r1_sha256
                0x0804, // rsa_pss_rsae_sha256
                0x0401, // rsa_pkcs1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0203, // ecdsa_sha1
                0x0805, // rsa_pss_rsae_sha384
                0x0805, // rsa_pss_rsae_sha384 (дважды — так в исходнике uTLS)
                0x0501, // rsa_pkcs1_sha384
                0x0806, // rsa_pss_rsae_sha512
                0x0601, // rsa_pkcs1_sha512
                0x0201, // rsa_pkcs1_sha1
            ],
        )),
        fixed_slot(generic::empty(18)), // signed_certificate_timestamp
        fixed_slot(key_share::encode(&[
            key_share::Entry {
                group: grease.group,
                data: &[0],
            },
            key_share::Entry {
                group: CURVE_X25519,
                data: &x25519.public,
            },
        ])),
        fixed_slot(generic::u8_list(45, &[1])), // psk_key_exchange_modes
        fixed_slot(generic::u16_list_u8_len(
            43, // supported_versions
            &[grease.version, 0x0304, 0x0303, 0x0302, 0x0301],
        )),
        fixed_slot(generic::u16_list_u8_len(27, &[0x0001])), // compress_certificate: zlib
        fixed_slot(grease_placeholder(grease.extension_last, &[0])),
    ];
    // `padding` добавляется отдельно при сборке всего `ClientHello`, как и у
    // Chrome, — см. `crate::fingerprint::Fingerprint::has_padding`.

    Ok((extensions, vec![x25519]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_cipher_is_grease_and_the_order_never_changes() {
        let mut first_run = rand::rngs::mock::StepRng::new(1, 1);
        let mut second_run = rand::rngs::mock::StepRng::new(1, 1);
        assert!(crate::grease::is_grease(CIPHER_SUITES[0]));
        let (a, _) = build(&mut first_run, "example.com").expect("собирается");
        let (b, _) = build(&mut second_run, "example.com").expect("собирается");
        assert!(
            a.iter().all(|e| e.anchored),
            "Safari не перемешивает порядок"
        );
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn there_is_no_session_ticket_alps_or_ech_grease() {
        let mut rng = rand::rngs::mock::StepRng::new(1, 1);
        let (extensions, _) = build(&mut rng, "example.com").expect("собирается");
        for ext_type in [35u16, 17513, 0xfe0d] {
            assert!(
                extensions
                    .iter()
                    .all(|e| !e.bytes.starts_with(&ext_type.to_be_bytes())),
                "расширения {ext_type:#06x} у HelloSafari_16_0 в uTLS нет"
            );
        }
    }

    #[test]
    fn certificate_compression_is_zlib_not_brotli() {
        let mut rng = rand::rngs::mock::StepRng::new(1, 1);
        let (extensions, _) = build(&mut rng, "example.com").expect("собирается");
        let compress = extensions
            .iter()
            .find(|e| e.bytes.starts_with(&27u16.to_be_bytes()))
            .expect("compress_certificate есть")
            .bytes
            .clone();
        assert_eq!(&compress[compress.len() - 2..], &1u16.to_be_bytes());
    }
}
