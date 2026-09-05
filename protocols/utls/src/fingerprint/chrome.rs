//! Chrome 120 (ноябрь 2023, `HelloChrome_120` в uTLS, `u_parrots.go` на
//! ревизии `23b1dac`).
//!
//! # Почему именно 120, а не свежее
//!
//! С Chrome 124 набор кривых в `key_share` включает гибрид
//! `X25519Kyber768Draft00`/`X25519MLKEM768` — постквантовый ключ поверх
//! обычного. Чтобы отпечаток был не витриной, а рабочим байтом, `key_share`
//! из этого крейта обязан нести настоящий ключ (см. `crate::key_exchange`):
//! сервер, не узнавший клиента по `SessionID`, перешлёт `ClientHello`
//! настоящему сайту, и тот попробует довершить рукопожатие тем ключом,
//! который назван. Ни в этом крейте, ни в проекте нет ML-KEM — своя
//! реализация была бы отдельной задачей, которую этот шаг фазы 19 явно не
//! включает. 120 — последняя версия в списке uTLS без гибрида: отпечаток
//! чуть более узнаваемый как «не самый свежий Chrome», но каждый байт в нём
//! рабочий.
//!
//! # GREASE и перемешивание
//!
//! Chrome (как и весь BoringSSL) добавляет GREASE — см. `crate::grease` — и
//! с версии 106 перемешивает расширения при каждом соединении
//! (`ShuffleChromeTLSExtensions` в uTLS). Перемешиваются не все: оба
//! псевдорасширения GREASE и `padding` держат свои позиции — первое перед
//! SNI, второе перед самым концом, padding — правда в самом конце. Причина
//! не в вежливости к серверу, а в самом алгоритме uTLS: перестановка
//! Фишера-Йетса пропускает обмен всякий раз, когда одна из двух переставляемых
//! позиций занята GREASE- или padding-расширением, поэтому такие позиции не
//! трогает ни один обмен за весь проход, и это следует правильно
//! воспроизвести, а не «примерно так же перемешать». Расширение
//! `encrypted_client_hello` (тоже GREASE, но не через `UtlsGREASEExtension`)
//! в число неприкасаемых не входит и перемешивается вместе с остальными —
//! это тоже видно из типов, которые `skipShuf` в uTLS считает якорями.
//!
//! Сверка: JA3/JA4 в открытом виде для конкретно Chrome 120 не нашёлся —
//! современные базы фиксируют версии начиная примерно с той, где сменился
//! набор кривых, а старые обычно без указания точной подверсии. Список
//! шифров, набор расширений и форма `padding` сверены только с исходником
//! uTLS; независимого захвата трафика для сверки байт в байт нет.

use rand::RngCore;

use crate::client_hello::ExtensionSlot;
use crate::error::UtlsResult;
use crate::extension::{ech_grease, fixed, generic, grease_placeholder, key_share, sni};
use crate::grease::GreaseValues;
use crate::key_exchange::{self, KeyExchange};

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

/// Единственный метод сжатия — TLS 1.3 запрещает любой, кроме этого, но поле
/// осталось от совместимости и должно быть заполнено.
pub const COMPRESSION_METHODS: &[u8] = &[0];

const CURVE_X25519: u16 = 29;
const CURVE_P256: u16 = 23;
const CURVE_P384: u16 = 24;
const EXT_APPLICATION_SETTINGS: u16 = 17513;

/// Длины полезной нагрузки GREASE ECH, которые предлагает `BoringGREASEECH()`
/// — умолчание BoringSSL, которым пользуется Chrome.
const ECH_GREASE_PAYLOAD_LENS: &[u16] = &[128, 160, 192, 224];

/// `BoringGREASEECH()` называет только один кандидат AEAD — в отличие от
/// Firefox, у которого их два (`crate::fingerprint::firefox`).
const ECH_GREASE_AEADS: &[u16] = &[ech_grease::AEAD_AES_128_GCM];

/// Собирает расширения и запрашивает пару ключей `X25519` для `key_share`.
pub(crate) fn build(
    rng: &mut impl RngCore,
    host: &str,
) -> UtlsResult<(Vec<ExtensionSlot>, Vec<KeyExchange>)> {
    let grease = GreaseValues::from_rng(rng);
    let system_rng = ring::rand::SystemRandom::new();
    let x25519 = key_exchange::generate_x25519(&system_rng)?;

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
    // `padding` сюда не входит: он не участвует в перемешивании и добавляется
    // последним уже при сборке всего `ClientHello` — там известна итоговая
    // длина, от которой и зависит, нужен ли он вообще
    // (`crate::fingerprint::Fingerprint::has_padding`).

    Ok((extensions, vec![x25519]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_cipher_and_the_first_and_last_extensions_are_grease() {
        let mut rng = rand::rngs::mock::StepRng::new(1, 1);
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
        let mut rng = rand::rngs::mock::StepRng::new(1, 1);
        let (extensions, _) = build(&mut rng, "example.com").expect("собирается");
        let free = extensions.iter().filter(|e| !e.anchored).count();
        assert_eq!(free, 16, "ECH GREASE тоже перемешивается — это не якорь");
    }

    #[test]
    fn the_group_grease_value_matches_between_curves_and_key_share() {
        // Обе группы GREASE берутся из одной и той же роли (`grease.group`):
        // сервер видит одно и то же число дважды, как у настоящего Chrome.
        let mut rng = rand::rngs::mock::StepRng::new(5, 7);
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
