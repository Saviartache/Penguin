//! Сборка `ClientHello` из частей отпечатка (`crate::fingerprint`): перемешивание
//! расширений и padding. Padding считается по длине сообщения без него (uTLS
//! `MarshalClientHelloNoECH`).

use crate::extension::padding;
use crate::record;
use crate::rng::Rng;

/// Закодированное расширение; якорь не сдвигается при перемешивании.
pub(crate) struct ExtensionSlot {
    pub(crate) bytes: Vec<u8>,
    pub(crate) anchored: bool,
}

/// Поля тела `ClientHello`, общие для всех отпечатков.
pub(crate) struct Fields<'a> {
    pub(crate) random: [u8; 32],
    pub(crate) session_id: [u8; 32],
    pub(crate) cipher_suites: &'a [u16],
    pub(crate) compression_methods: &'a [u8],
    pub(crate) extensions: Vec<ExtensionSlot>,
}

/// Собирает сообщение `ClientHello` одним проходом, без промежуточных буферов.
///
/// `has_padding` — padding по правилу BoringSSL; `shuffle` — перемешать расширения.
pub(crate) fn assemble(
    mut fields: Fields<'_>,
    shuffle: bool,
    has_padding: bool,
    rng: &mut impl Rng,
) -> Vec<u8> {
    if shuffle {
        shuffle_with_anchors(&mut fields.extensions, rng);
    }

    let extensions_len: usize = fields.extensions.iter().map(|s| s.bytes.len()).sum();
    let head_len = 2
        + 32
        + 1
        + fields.session_id.len()
        + 2
        + fields.cipher_suites.len() * 2
        + 1
        + fields.compression_methods.len();
    let unpadded_len = 4 + head_len + list_overhead(extensions_len);
    let padding_len = has_padding
        .then(|| padding::extra_len(unpadded_len + extensions_len))
        .flatten();
    let total_extensions = extensions_len + padding_len.map_or(0, |extra| 4 + extra);

    let body_len = head_len + list_overhead(total_extensions) + total_extensions;
    let mut out = Vec::with_capacity(4 + body_len);
    out.extend_from_slice(&record::handshake_header(
        record::HANDSHAKE_TYPE_CLIENT_HELLO,
        body_len,
    ));
    out.extend_from_slice(&record::LEGACY_VERSION.to_be_bytes());
    out.extend_from_slice(&fields.random);
    out.push(fields.session_id.len() as u8);
    out.extend_from_slice(&fields.session_id);
    out.extend_from_slice(&((fields.cipher_suites.len() * 2) as u16).to_be_bytes());
    for suite in fields.cipher_suites {
        out.extend_from_slice(&suite.to_be_bytes());
    }
    out.push(fields.compression_methods.len() as u8);
    out.extend_from_slice(fields.compression_methods);
    if total_extensions > 0 {
        out.extend_from_slice(&(total_extensions as u16).to_be_bytes());
        for slot in &fields.extensions {
            out.extend_from_slice(&slot.bytes);
        }
        if let Some(extra) = padding_len {
            out.extend_from_slice(&padding::encode(extra));
        }
    }
    out
}

/// Длина префикса списка расширений: пустой список опускается (RFC 8446 §4.1.2).
fn list_overhead(extensions_len: usize) -> usize {
    if extensions_len == 0 { 0 } else { 2 }
}

/// Фишер-Йетс, пропускающий обмен, если одна из позиций занята якорем:
/// якорь не сдвигается никогда (так GREASE остаётся первым и предпоследним).
fn shuffle_with_anchors(slots: &mut [ExtensionSlot], rng: &mut impl Rng) {
    for i in (1..slots.len()).rev() {
        let j = ((u64::from(rng.next_u32()) * (i as u64 + 1)) >> 32) as usize;
        if slots[i].anchored || slots[j].anchored {
            continue;
        }
        slots.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::testing::{SeededRng, StepRng};

    fn slot(anchored: bool, byte: u8) -> ExtensionSlot {
        ExtensionSlot {
            bytes: vec![byte],
            anchored,
        }
    }

    #[test]
    fn anchored_slots_never_move() {
        let mut rng = SeededRng(42);
        for _ in 0..200 {
            let mut slots = vec![
                slot(true, 0xAA),
                slot(false, 1),
                slot(false, 2),
                slot(false, 3),
                slot(true, 0xBB),
            ];
            shuffle_with_anchors(&mut slots, &mut rng);
            assert_eq!(slots.first().expect("есть").bytes, vec![0xAA]);
            assert_eq!(slots.last().expect("есть").bytes, vec![0xBB]);
        }
    }

    #[test]
    fn unanchored_slots_do_get_reordered_eventually() {
        let mut rng = SeededRng(7);
        let original = [1u8, 2, 3, 4, 5];
        let mut changed = false;
        for _ in 0..50 {
            let mut slots: Vec<_> = original.iter().map(|&b| slot(false, b)).collect();
            shuffle_with_anchors(&mut slots, &mut rng);
            let order: Vec<u8> = slots.iter().map(|s| s.bytes[0]).collect();
            if order != original {
                changed = true;
                break;
            }
        }
        assert!(changed, "за 50 попыток порядок ни разу не изменился");
    }

    fn fields_with_sni(host: &str) -> Fields<'static> {
        Fields {
            random: [0; 32],
            session_id: [0; 32],
            cipher_suites: &[0x1301],
            compression_methods: &[0],
            extensions: vec![ExtensionSlot {
                bytes: crate::extension::sni::encode(host),
                anchored: true,
            }],
        }
    }

    #[test]
    fn a_short_hello_is_not_padded() {
        let bytes = assemble(
            fields_with_sni("a.io"),
            false,
            true,
            &mut StepRng::new(0, 0),
        );
        assert!(
            bytes.len() < 0x100,
            "короткий ClientHello не должен получить padding"
        );
    }

    #[test]
    fn padding_brings_the_hello_up_to_exactly_512_bytes() {
        let host = "a".repeat(300) + ".example.com";
        let bytes = assemble(fields_with_sni(&host), false, true, &mut StepRng::new(0, 0));
        assert_eq!(bytes.len(), 0x200, "запись должна выйти ровно на 512 байт");
    }

    #[test]
    fn without_has_padding_nothing_is_added_even_in_the_danger_zone() {
        let host = "a".repeat(300) + ".example.com";
        let with_padding = assemble(fields_with_sni(&host), false, true, &mut StepRng::new(0, 0));
        let without_padding = assemble(
            fields_with_sni(&host),
            false,
            false,
            &mut StepRng::new(0, 0),
        );
        assert!(without_padding.len() < with_padding.len());
    }
}
