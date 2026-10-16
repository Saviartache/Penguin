//! Chrome 120 (`HelloChrome_120`, uTLS `u_parrots.go`, ревизия `23b1dac`).
//!
//! 120 — последняя версия без постквантового гибрида: ML-KEM в проекте нет.
//! Перемешиваются все расширения, кроме двух GREASE-якорей (и padding).
//! Сверено только с исходником uTLS, не с захватом трафика.

use crate::client_hello::ExtensionSlot;
use crate::error::UtlsResult;
use crate::extension::{ech_grease, fixed, generic, grease_placeholder, key_share, sni};
use crate::grease::GreaseValues;
use crate::key_exchange::{self, KeyExchange};
use crate::rng::Rng;

/// Шифры, точно в этом порядке. Первый — место GREASE.
pub const CIPHER_SUITES: &[u16] = &[
    crate::grease::PLACEHOLDER,
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
    0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
    0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
    0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
];

/// Метод сжатия: только `null`.
pub const COMPRESSION_METHODS: &[u8] = &[0];

const CURVE_X25519: u16 = 29;
const CURVE_P256: u16 = 23;
const CURVE_P384: u16 = 24;
const EXT_APPLICATION_SETTINGS: u16 = 17513;

/// Длины нагрузки GREASE ECH по `BoringGREASEECH()`.
const ECH_GREASE_PAYLOAD_LENS: &[u16] = &[128, 160, 192, 224];

const ECH_GREASE_AEADS: &[u16] = &[ech_grease::AEAD_AES_128_GCM];

/// Собирает расширения и запрашивает пару ключей `X25519` для `key_share`.
pub(crate) fn build(
    rng: &mut impl Rng,
    host: &str,
) -> UtlsResult<(Vec<ExtensionSlot>, Vec<KeyExchange>)> {
    let grease = GreaseValues::from_rng(rng);
    let x25519 = key_exchange::generate_x25519();

    let shuffleable = |bytes: Vec<u8>| ExtensionSlot {
        bytes,
        anchored: false,
    };
    let anchored = |bytes: Vec<u8>| ExtensionSlot {
        bytes,
        anchored: true,
    };

    let extensions = vec![
        anchored(grease_placeholder(grease.extension_first, &[])),
        shuffleable(sni::encode(host)),
        shuffleable(generic::empty(23)), // extended_master_secret
        shuffleable(fixed::renegotiation_info()),
        shuffleable(generic::u16_list_u16_len(
            10, // supported_groups
            &[grease.group, CURVE_X25519, CURVE_P256, CURVE_P384],
        )),
        shuffleable(generic::u8_list(11, &[0])), // ec_point_formats: uncompressed
        shuffleable(generic::empty(35)),         // session_ticket, без билета
        shuffleable(generic::string_list(
            16, // alpn
            &[
                penguin_transport::tls::ALPN_H2,
                penguin_transport::tls::ALPN_HTTP11,
            ],
        )),
        shuffleable(fixed::status_request()),
        shuffleable(generic::u16_list_u16_len(
            13, // signature_algorithms
            &[
                0x0403, // ecdsa_secp256r1_sha256
                0x0804, // rsa_pss_rsae_sha256
                0x0401, // rsa_pkcs1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0805, // rsa_pss_rsae_sha384
                0x0501, // rsa_pkcs1_sha384
                0x0806, // rsa_pss_rsae_sha512
                0x0601, // rsa_pkcs1_sha512
            ],
        )),
        shuffleable(generic::empty(18)), // signed_certificate_timestamp
        shuffleable(key_share::encode(&[
            key_share::Entry {
                group: grease.group,
                data: &[0],
            },
            key_share::Entry {
                group: CURVE_X25519,
                data: &x25519.public,
            },
        ])),
        shuffleable(generic::u8_list(45, &[1])), // psk_key_exchange_modes: psk_dhe_ke
        shuffleable(generic::u16_list_u8_len(
            43, // supported_versions
            &[grease.version, 0x0304, 0x0303],
        )),
        shuffleable(generic::u16_list_u8_len(27, &[0x0002])), // compress_certificate: brotli
        shuffleable(generic::string_list(
            EXT_APPLICATION_SETTINGS,
            &[penguin_transport::tls::ALPN_H2],
        )),
        shuffleable(ech_grease::encode(
            rng,
            ECH_GREASE_AEADS,
            ECH_GREASE_PAYLOAD_LENS,
        )),
        anchored(grease_placeholder(grease.extension_last, &[0])),
    ];

    Ok((extensions, vec![x25519]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::testing::StepRng;

    #[test]
    fn the_first_cipher_and_the_first_and_last_extensions_are_grease() {
        let mut rng = StepRng::new(1, 1);
        let (extensions, keys) = build(&mut rng, "example.com").expect("собирается");
        assert!(crate::grease::is_grease(CIPHER_SUITES[0]));
        assert!(
            extensions.first().expect("есть").anchored,
            "GREASE1 перед SNI"
        );
        assert!(
            extensions.last().expect("есть").anchored,
            "GREASE2 — последнее расширение до padding, который добавляют отдельно"
        );
        assert_eq!(keys.len(), 1, "Chrome предлагает один настоящий ключ");
    }

    #[test]
    fn sixteen_extensions_in_the_middle_are_not_anchored() {
        let mut rng = StepRng::new(1, 1);
        let (extensions, _) = build(&mut rng, "example.com").expect("собирается");
        let free = extensions.iter().filter(|e| !e.anchored).count();
        assert_eq!(free, 16, "ECH GREASE тоже перемешивается — это не якорь");
    }

    #[test]
    fn the_group_grease_value_matches_between_curves_and_key_share() {
        // Обе группы GREASE берутся из одной и той же роли (`grease.group`):
        // сервер видит одно и то же число дважды, как у настоящего Chrome.
        let mut rng = StepRng::new(5, 7);
        let (extensions, _) = build(&mut rng, "example.com").expect("собирается");
        let curves = extensions
            .iter()
            .find(|e| e.bytes.starts_with(&10u16.to_be_bytes()))
            .expect("supported_groups есть")
            .bytes
            .clone();
        let key_share = extensions
            .iter()
            .find(|e| e.bytes.starts_with(&51u16.to_be_bytes()))
            .expect("key_share есть")
            .bytes
            .clone();
        let curve_grease = u16::from_be_bytes([curves[6], curves[7]]);
        let key_share_grease = u16::from_be_bytes([key_share[6], key_share[7]]);
        assert_eq!(curve_grease, key_share_grease);
    }
}
