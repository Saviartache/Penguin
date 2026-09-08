//! `Addons` — сообщение из заголовка VLESS, несущее `flow`.
//!
//! `XTLS/Xray-core`, `proxy/vless/encoding/addons.proto`:
//!
//! ```text
//! message Addons {
//!   string Flow = 1;
//!   bytes Seed = 2;
//! }
//! ```
//!
//! `Seed` эта реализация никогда не заполняет, а `proto3` не пишет на
//! проводе пустое/умолчательное поле — значит, всё сообщение сводится к
//! одному полю `Flow`. Тег поля — не константа эталона, а обычная формула
//! protobuf (`(номер_поля << 3) | тип_провода`, тип `2` — `bytes`/`string`,
//! `docs.protobuf.dev/programming-guides/encoding`), поэтому она не в счёт
//! правила 8.1: этот кусок можно пересчитать по стандарту, а не подсмотреть
//! в исходнике.
//!
//! `EncodeHeaderAddons` (`proxy/vless/encoding/encoding.go`) кодирует
//! протобуф только в ветке `addons.Flow == vless.XRV` — любое другое
//! значение `Flow` (пустое или нет) уходит как пустой `Addons` (длина ноль).
//! `validate()` (`crate::config`) не пускает сюда ничего, кроме этих двух
//! случаев, но кодировщик всё равно проверяет по значению, а не по факту
//! вызова — так он остаётся верным сам по себе, а не только благодаря
//! проверке снаружи.

/// Единственное значение `flow`, которое понимает эта реализация.
pub const FLOW_VISION: &str = "xtls-rprx-vision";

/// Тег поля `Flow = 1` (`addons.proto`) в кодировке protobuf: номер поля `1`,
/// сдвинутый на три бита, и тип провода `2` (`bytes`/`string`) в младших
/// битах.
const FLOW_FIELD_TAG: u8 = (1 << 3) | 2;

/// Пишет сегмент `Addons` заголовка VLESS: один байт длины и, если он не
/// ноль, сам протобуф следом.
pub fn encode(flow: Option<&str>, out: &mut Vec<u8>) {
    if flow != Some(FLOW_VISION) {
        out.push(0);
        return;
    }

    let flow_bytes = FLOW_VISION.as_bytes();
    // Варинт длины умещается в один байт, пока имя `flow` короче 128 байт —
    // с запасом верно для `FLOW_VISION` (16 байт) и любого другого разумного
    // имени.
    debug_assert!(flow_bytes.len() < 0x80);

    let message_len = 2 + flow_bytes.len();
    out.push(message_len as u8);
    out.push(FLOW_FIELD_TAG);
    out.push(flow_bytes.len() as u8);
    out.extend_from_slice(flow_bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flow_writes_a_single_zero_byte() {
        let mut out = Vec::new();
        encode(None, &mut out);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn an_unsupported_flow_is_the_same_as_none_on_the_wire() {
        // `EncodeHeaderAddons` кодирует протобуф только для `vless.XRV`;
        // любое другое имя (сюда `validate()` уже не пускает, но кодировщик
        // не должен полагаться на это) уходит как пустой `Addons`.
        let mut out = Vec::new();
        encode(Some("xtls-rprx-splice"), &mut out);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn vision_is_the_length_byte_and_the_protobuf_message() {
        // `0x0a` — тег поля 1, тип bytes/string; `0x10` — длина строки (16);
        // посчитано и независимо третьей стороной (`python3`, реализация
        // protobuf-варинтов из стандарта) — см. отчёт о задаче.
        let mut out = Vec::new();
        encode(Some(FLOW_VISION), &mut out);
        let mut expected = vec![0x12, 0x0a, 0x10];
        expected.extend_from_slice(FLOW_VISION.as_bytes());
        assert_eq!(out, expected);
    }
}
