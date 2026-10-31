//! Сборка `ClientHello` из частей отпечатка (`crate::fingerprint`) и перемешивание
//! расширений.

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
/// `shuffle` — перемешать расширения.
pub(crate) fn assemble(mut fields: Fields<'_>, shuffle: bool, rng: &mut impl Rng) -> Vec<u8> {
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
    let body_len = head_len + list_overhead(extensions_len) + extensions_len;
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
    if extensions_len > 0 {
        out.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        for slot in &fields.extensions {
            out.extend_from_slice(&slot.bytes);
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
    fn the_declared_lengths_match_the_bytes() {
        let bytes = assemble(fields_with_sni("a.io"), false, &mut StepRng::new(0, 0));
        let body_len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(body_len + 4, bytes.len());
        let sni_len = crate::extension::sni::encode("a.io").len();
        let list_len = u16::from_be_bytes([
            bytes[bytes.len() - sni_len - 2],
            bytes[bytes.len() - sni_len - 1],
        ]);
        assert_eq!(usize::from(list_len), sni_len);
    }
}
