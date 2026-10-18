//! Пакеты-сигнатуры `I1`–`I5`: цепочка тегов, разобранная как `newObfChain`
//! (`device/obf.go`). Клиент их только шлёт перед рукопожатием, и эталон
//! собирает их как `Obfuscate(buf, nil)`: теги данных `<d>` и `<ds>` дают пусто,
//! `<dz n>` — `n` нулевых байт (длина пустых данных). Текст вне тегов не значит ничего.

use std::time::{SystemTime, UNIX_EPOCH};

use penguin_proto::random;

/// Алфавит `<rc>` (`chars52`).
const LETTERS: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Алфавит `<rd>` (`digits10`).
const DIGITS: &[u8; 10] = b"0123456789";

/// Один тег цепочки.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Tag {
    /// `<b 0x…>`: байты как есть.
    Bytes(Vec<u8>),
    /// `<r n>`: случайные байты.
    Random(usize),
    /// `<rc n>`: случайные латинские буквы.
    Letters(usize),
    /// `<rd n>`: случайные цифры.
    Digits(usize),
    /// `<t>`: время UNIX, 4 байта big-endian.
    Timestamp,
    /// `<dz n>`: длина пустых данных в `n` байтах — нули.
    Zeros(usize),
    /// `<d>`, `<ds>`: пустые данные.
    Empty,
}

/// Разобранная цепочка одного `Ix`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Chain(Vec<Tag>);

impl Chain {
    /// Разбирает запись; `None` — в ней нет ни одного тега (эталон пакет пропускает).
    pub(super) fn parse(spec: &str) -> Result<Option<Self>, String> {
        let mut tags = Vec::new();
        let mut rest = spec;
        while let Some(open) = rest.find('<') {
            let close = rest[open..].find('>').ok_or("нет закрывающей `>`")? + open;
            tags.push(parse_tag(&rest[open + 1..close])?);
            rest = &rest[close + 1..];
        }
        Ok((!tags.is_empty()).then_some(Self(tags)))
    }

    /// Собирает пакет.
    pub(super) fn generate(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for tag in &self.0 {
            match tag {
                Tag::Bytes(bytes) => out.extend_from_slice(bytes),
                Tag::Random(n) => extend_random(&mut out, *n),
                Tag::Letters(n) => extend_from_alphabet(&mut out, *n, LETTERS),
                Tag::Digits(n) => extend_from_alphabet(&mut out, *n, DIGITS),
                Tag::Timestamp => out.extend_from_slice(&unix_seconds().to_be_bytes()),
                Tag::Zeros(n) => out.resize(out.len() + n, 0),
                Tag::Empty => {}
            }
        }
        out
    }
}

/// Разбирает содержимое `<…>`: ключ и необязательное значение через пробел.
fn parse_tag(inner: &str) -> Result<Tag, String> {
    let mut parts = inner.split_whitespace();
    let key = parts.next().ok_or("пустой тег")?;
    let value = parts.next().unwrap_or("");
    let length = || {
        value
            .parse::<usize>()
            .map_err(|e| format!("длина в `<{inner}>`: {e}"))
    };
    Ok(match key {
        "b" => Tag::Bytes(parse_hex(value).map_err(|e| format!("`<{inner}>`: {e}"))?),
        "r" => Tag::Random(length()?),
        "rc" => Tag::Letters(length()?),
        "rd" => Tag::Digits(length()?),
        "dz" => Tag::Zeros(length()?),
        "t" => Tag::Timestamp,
        "d" | "ds" => Tag::Empty,
        _ => return Err(format!("неизвестный тег `<{key}>`")),
    })
}

/// Байты из hex с необязательным `0x` (`newBytesObf`).
fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if digits.is_empty() {
        return Err("пустые байты".to_owned());
    }
    if !digits.len().is_multiple_of(2) {
        return Err("нечётное число знаков".to_owned());
    }
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or_else(|| format!("не hex: `{}`", String::from_utf8_lossy(pair)))
        })
        .collect()
}

fn extend_random(out: &mut Vec<u8>, n: usize) {
    let from = out.len();
    out.resize(from + n, 0);
    random::fill(&mut out[from..]);
}

/// Случайный байт по модулю длины алфавита — как эталон.
fn extend_from_alphabet(out: &mut Vec<u8>, n: usize, alphabet: &[u8]) {
    let from = out.len();
    extend_random(out, n);
    for byte in &mut out[from..] {
        *byte = alphabet[usize::from(*byte) % alphabet.len()];
    }
}

/// Часы до 1970-го — ноль, а не паника.
fn unix_seconds() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(spec: &str) -> Chain {
        Chain::parse(spec).expect("разбирается").expect("есть теги")
    }

    #[test]
    fn static_bytes_are_dumped_as_is() {
        assert_eq!(chain("<b 0xc0ffee>").generate(), vec![0xc0, 0xff, 0xee]);
        assert_eq!(chain("<b c0ffee>").generate(), vec![0xc0, 0xff, 0xee]);
    }

    #[test]
    fn tags_follow_each_other_in_order_with_their_lengths() {
        let packet = chain("<b 0xAABB><r 5><rc 7><rd 3><t><dz 2><d><ds>").generate();
        assert_eq!(packet.len(), 2 + 5 + 7 + 3 + 4 + 2);
        assert_eq!(&packet[..2], &[0xAA, 0xBB]);
        assert!(
            packet[7..14].iter().all(u8::is_ascii_alphabetic),
            "{packet:?}"
        );
        assert!(packet[14..17].iter().all(u8::is_ascii_digit), "{packet:?}");
        assert_eq!(&packet[21..23], &[0, 0]);
    }

    #[test]
    fn the_timestamp_is_big_endian_unix_seconds() {
        let before = unix_seconds();
        let packet = chain("<t>").generate();
        let stamp = u32::from_be_bytes(packet.try_into().expect("4 байта"));
        assert!(
            stamp >= before && stamp <= before + 2,
            "{stamp} vs {before}"
        );
    }

    #[test]
    fn text_outside_tags_is_ignored_and_no_tags_means_no_packet() {
        assert_eq!(chain("мусор<b 0x01>хвост").generate(), vec![1]);
        assert_eq!(Chain::parse("без тегов").expect("разбирается"), None);
        assert_eq!(Chain::parse("").expect("разбирается"), None);
    }

    #[test]
    fn malformed_chains_are_refused() {
        for bad in [
            "<b 0x1>", "<b 0xZZ>", "<b>", "<r>", "<r x>", "<rc -1>", "<q 1>", "<>", "<b 0x01",
        ] {
            assert!(Chain::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_real_world_quic_like_signature_parses() {
        // Вид, в каком Amnezia выдаёт `I1`: длинный статический префикс и случайный хвост.
        let spec = "<b 0xc70000000108ce1bf31eec7d93360000449e227e4596ed7f75c4d35ce31880b4133107c822c6355d51f0d908c6>\
                    <r 16><t>";
        let packet = chain(spec).generate();
        assert_eq!(packet.len(), 45 + 16 + 4);
        assert_eq!(packet[0], 0xc7);
    }
}
