//! Сборка готового сообщения `ClientHello` из частей, которые собрал
//! конкретный отпечаток (`crate::fingerprint`).
//!
//! ```text
//! +---------+--------+------------+-----+---------+------+-------------+------------+
//! | legacy_ | random | session_id | шифры | сжатие | расширения (если есть)   |
//! | version |        |            |       |        |                          |
//! +---------+--------+------------+-----+---------+------+-------------+------------+
//! |    2    |   32   |  1+до 32   | 2+2n|   1+1   |         2 + сумма длин      |
//! +---------+--------+------------+-----+---------+------+-------------+------------+
//! ```
//!
//! Два момента здесь не очевидны из RFC 8446 и решают судьбу отпечатка:
//!
//! - **Порядок расширений после перемешивания** — не решение этого модуля, а
//!   решение отпечатка (`shuffle: bool` в [`crate::fingerprint::Fingerprint`]).
//!   Здесь только сам алгоритм перестановки с якорями, общий для всех, кто
//!   пожелает им воспользоваться.
//! - **`padding` считается по итоговой длине без него самого** — это в
//!   точности то, что делает `MarshalClientHelloNoECH` в uTLS: собрать всё,
//!   что не padding, посчитать длину получившегося сообщения целиком (с
//!   заголовком рукопожатия!) и только по ней решить, нужен ли паддинг и
//!   какой длины.

use rand::{Rng, RngCore};

use crate::extension::padding;
use crate::record;

/// Одно закодированное расширение и то, можно ли переставить его местами с
/// соседями при перемешивании.
///
/// GREASE-псевдорасширения — якоря всегда: перестановка BoringSSL никогда не
/// трогает позиции, которые они занимают (см. `crate::fingerprint::chrome`).
/// У отпечатков без перемешивания (Firefox, Safari) якорь — вообще всё:
/// `shuffle: false` у `Fingerprint` делает поле неважным для итогового
/// порядка, но не для чтения кода — то, что Chrome ставит явно, у остальных
/// не должно выглядеть как забытая настройка.
pub(crate) struct ExtensionSlot {
    pub(crate) bytes: Vec<u8>,
    pub(crate) anchored: bool,
}

/// Поля тела `ClientHello`, общие для любого отпечатка — то, чем можно
/// пользоваться, ничего не зная про перемешивание и `padding`.
///
/// Собрано в одну структуру не ради красоты, а потому что `assemble` иначе
/// получил бы восемь параметров подряд, и порядок «какой байтовый массив
/// какому полю» пришлось бы держать в голове на каждом вызове.
pub(crate) struct Fields<'a> {
    pub(crate) random: [u8; 32],
    pub(crate) session_id: [u8; 32],
    pub(crate) cipher_suites: &'a [u16],
    pub(crate) compression_methods: &'a [u8],
    pub(crate) extensions: Vec<ExtensionSlot>,
}

/// Собирает сообщение `ClientHello`: заголовок рукопожатия и тело.
///
/// `has_padding` — использует ли отпечаток `padding` по правилу BoringSSL
/// (Chrome, Safari); `shuffle` — перемешивает ли он расширения (только
/// Chrome, начиная с версии 106).
pub(crate) fn assemble(
    mut fields: Fields<'_>,
    shuffle: bool,
    has_padding: bool,
    rng: &mut impl RngCore,
) -> Vec<u8> {
    if shuffle {
        shuffle_with_anchors(&mut fields.extensions, rng);
    }

    let mut extensions_bytes = Vec::new();
    for slot in &fields.extensions {
        extensions_bytes.extend_from_slice(&slot.bytes);
    }

    let without_padding = build_message(&fields, &extensions_bytes);

    if has_padding && let Some(extra) = padding::extra_len(without_padding.len()) {
        extensions_bytes.extend_from_slice(&padding::encode(extra));
        return build_message(&fields, &extensions_bytes);
    }

    without_padding
}

fn build_message(fields: &Fields<'_>, extensions_bytes: &[u8]) -> Vec<u8> {
    let session_id = fields.session_id;
    let cipher_suites = fields.cipher_suites;
    let compression_methods = fields.compression_methods;

    let mut body = Vec::with_capacity(
        2 + 32 + 1 + session_id.len() + 2 + cipher_suites.len() * 2 + 1 + compression_methods.len(),
    );
    body.extend_from_slice(&record::LEGACY_VERSION.to_be_bytes());
    body.extend_from_slice(&fields.random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(&session_id);
    body.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
    for suite in cipher_suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    body.push(compression_methods.len() as u8);
    body.extend_from_slice(compression_methods);
    // TLS 1.3 всегда шлёт хотя бы одно расширение, но правило общее: список
    // расширений опускается целиком, если он пуст (RFC 8446 §4.1.2).
    if !extensions_bytes.is_empty() {
        body.extend_from_slice(&(extensions_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions_bytes);
    }
    record::wrap_handshake(record::HANDSHAKE_TYPE_CLIENT_HELLO, &body)
}

/// Перестановка Фишера-Йетса, которая пропускает обмен всякий раз, когда
/// одна из двух переставляемых позиций занята якорем.
///
/// Из-за этого правила якоря не просто «часто остаются на месте» — они не
/// сдвигаются вообще ни разу за весь проход, с самого первого столкновения:
/// как только элемент-якорь оказался в очередной позиции, эта позиция
/// больше не участвует ни в одном обмене до конца перестановки. Тем и
/// объясняется, что GREASE в Chrome всегда стоит первым и предпоследним,
/// хотя всё остальное между ними каждый раз новое.
fn shuffle_with_anchors(slots: &mut [ExtensionSlot], rng: &mut impl RngCore) {
    for i in (1..slots.len()).rev() {
        let j = rng.gen_range(0..=i);
        if slots[i].anchored || slots[j].anchored {
            continue;
        }
        slots.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    fn slot(anchored: bool, byte: u8) -> ExtensionSlot {
        ExtensionSlot {
            bytes: vec![byte],
            anchored,
        }
    }

    #[test]
    fn anchored_slots_never_move() {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(42);
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
        let mut rng = rand::rngs::SmallRng::seed_from_u64(7);
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

    /// Минимальные поля с одним расширением `server_name` — то, чего
    /// хватает, чтобы проверить `padding` в отрыве от конкретного отпечатка.
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
            &mut rand::rngs::mock::StepRng::new(0, 0),
        );
        assert!(
            bytes.len() < 0x100,
            "короткий ClientHello не должен получить padding"
        );
    }

    #[test]
    fn padding_brings_the_hello_up_to_exactly_512_bytes() {
        // Длинное имя хоста раздувает SNI ровно настолько, чтобы попасть в
        // опасный диапазон 256..512 без padding.
        let host = "a".repeat(300) + ".example.com";
        let bytes = assemble(
            fields_with_sni(&host),
            false,
            true,
            &mut rand::rngs::mock::StepRng::new(0, 0),
        );
        assert_eq!(bytes.len(), 0x200, "запись должна выйти ровно на 512 байт");
    }

    #[test]
    fn without_has_padding_nothing_is_added_even_in_the_danger_zone() {
        let host = "a".repeat(300) + ".example.com";
        let with_padding = assemble(
            fields_with_sni(&host),
            false,
            true,
            &mut rand::rngs::mock::StepRng::new(0, 0),
        );
        let without_padding = assemble(
            fields_with_sni(&host),
            false,
            false,
            &mut rand::rngs::mock::StepRng::new(0, 0),
        );
        assert!(without_padding.len() < with_padding.len());
    }
}
