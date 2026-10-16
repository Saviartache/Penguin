//! `padding` (21), RFC 7685, по схеме BoringSSL (uTLS `BoringPaddingStyle`):
//! hello длиной 256..511 байт добивается до 512.

/// Сколько байт тела добавить; `None` — не нужно. `unpadded_len` — длина hello без padding.
pub fn extra_len(unpadded_len: usize) -> Option<usize> {
    if unpadded_len <= 0xff || unpadded_len >= 0x200 {
        return None;
    }
    let target = 0x200 - unpadded_len;
    Some(if target >= 5 { target - 4 } else { 1 })
}

const EXTENSION_TYPE: u16 = 21;

/// Кодирует `padding` из `len` нулевых байт.
pub fn encode(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + len);
    out.extend_from_slice(&EXTENSION_TYPE.to_be_bytes());
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.resize(4 + len, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_hellos_are_left_alone() {
        assert_eq!(extra_len(0xff), None);
        assert_eq!(extra_len(10), None);
    }

    #[test]
    fn long_hellos_are_left_alone_too() {
        assert_eq!(extra_len(0x200), None);
        assert_eq!(extra_len(4000), None);
    }

    #[test]
    fn a_hello_in_the_dangerous_range_is_padded_to_exactly_512() {
        let unpadded = 0x1a0;
        let extra = extra_len(unpadded).expect("должен добавить паддинг");
        assert_eq!(unpadded + 4 + extra, 0x200);
    }

    #[test]
    fn right_at_the_boundary_the_header_exactly_fits() {
        // До 0x200 не хватает пяти байт — ровно заголовка расширения (4) и
        // одного байта тела: паддинг попадает в 0x200 без остатка.
        let unpadded = 0x1fb;
        let extra = extra_len(unpadded).expect("должен добавить паддинг");
        assert_eq!(extra, 1);
        assert_eq!(unpadded + 4 + extra, 0x200);
    }

    #[test]
    fn past_the_boundary_padding_overshoots_by_design() {
        // До 0x200 не хватает всего одного байта — меньше, чем весит сам
        // заголовок расширения. Один байт тела всё равно добавляется (иначе
        // запись так и останется в опасном диапазоне), но точно в 0x200
        // попасть уже не получится — так делает и сам BoringSSL.
        let unpadded = 0x1ff;
        let extra = extra_len(unpadded).expect("должен добавить паддинг");
        assert_eq!(extra, 1);
        assert_eq!(unpadded + 4 + extra, 0x204);
    }

    #[test]
    fn encoded_padding_is_all_zero_bytes() {
        let bytes = encode(3);
        assert_eq!(&bytes[0..2], &21u16.to_be_bytes());
        assert_eq!(&bytes[2..4], &3u16.to_be_bytes());
        assert_eq!(&bytes[4..], &[0, 0, 0]);
    }
}
