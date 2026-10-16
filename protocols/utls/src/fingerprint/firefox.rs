//! Firefox 120 (`HelloFirefox_120`, uTLS `u_parrots.go`, ревизия `23b1dac`).
//!
//! NSS: без GREASE и без перемешивания; в `key_share` настоящие X25519 и P-256.
//! Сверено только с исходником uTLS.

use crate::client_hello::ExtensionSlot;
use crate::error::UtlsResult;
use crate::extension::{ech_grease, fixed, generic, sni};
use crate::key_exchange::{self, KeyExchange};
use crate::rng::Rng;

/// Шифры, точно в этом порядке.
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

/// Метод сжатия: только `null`.
pub const COMPRESSION_METHODS: &[u8] = &[0];

const CURVE_X25519: u16 = 29;
const CURVE_P256: u16 = 23;
const CURVE_P384: u16 = 24;
const CURVE_P521: u16 = 25;
const GROUP_FFDHE2048: u16 = 0x0100;
const GROUP_FFDHE3072: u16 = 0x0101;

const ECH_GREASE_PAYLOAD_LENS: &[u16] = &[223];

const ECH_GREASE_AEADS: &[u16] = &[
    ech_grease::AEAD_AES_128_GCM,
    ech_grease::AEAD_CHACHA20_POLY1305,
];

/// Собирает расширения и запрашивает пары ключей `X25519` и `P-256`.
pub(crate) fn build(
    rng: &mut impl Rng,
    host: &str,
) -> UtlsResult<(Vec<ExtensionSlot>, Vec<KeyExchange>)> {
    let system_rng = ring::rand::SystemRandom::new();
    let x25519 = key_exchange::generate_x25519();
    let p256 = key_exchange::generate_p256(&system_rng)?;

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
            34, // delegated_credentials
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
            43, // supported_versions
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
    use crate::rng::testing::StepRng;

    #[test]
    fn no_cipher_or_extension_is_grease() {
        let mut rng = StepRng::new(1, 1);
        for cipher in CIPHER_SUITES {
            assert!(!crate::grease::is_grease(*cipher));
        }
        let (extensions, keys) = build(&mut rng, "example.com").expect("собирается");
        assert!(extensions.iter().all(|e| e.anchored), "порядок не меняется");
        assert_eq!(keys.len(), 2, "Firefox предлагает X25519 и P-256");
    }

    #[test]
    fn the_second_key_is_a_real_p256_point() {
        let mut rng = StepRng::new(9, 3);
        let (_, keys) = build(&mut rng, "example.com").expect("собирается");
        assert_eq!(keys[0].public.len(), 32, "первый ключ — X25519");
        assert_eq!(keys[1].public.len(), 65, "второй — несжатая точка P-256");
    }
}
