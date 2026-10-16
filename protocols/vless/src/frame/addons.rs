//! `Addons` заголовка VLESS (`proxy/vless/encoding/addons.proto`, `XTLS/Xray-core`):
//! `string Flow = 1; bytes Seed = 2;`. `Seed` не пишется, остаётся поле `Flow`.
//! Кодируется только `xtls-rprx-vision` (`EncodeHeaderAddons`), иначе длина ноль.

/// Единственное понимаемое значение `flow`.
pub const FLOW_VISION: &str = "xtls-rprx-vision";

/// Тег поля `Flow = 1` в protobuf: `(1 << 3) | 2`.
const FLOW_FIELD_TAG: u8 = (1 << 3) | 2;

/// Пишет `Addons`: байт длины и, если не ноль, protobuf.
pub fn encode(flow: Option<&str>, out: &mut Vec<u8>) {
    if flow != Some(FLOW_VISION) {
        out.push(0);
        return;
    }

    let flow_bytes = FLOW_VISION.as_bytes();
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
