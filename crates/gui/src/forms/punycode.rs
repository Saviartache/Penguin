//! Кириллические имена (`.рф`, `яндекс.рф`) в ASCII и обратно (RFC 3492).
//!
//! Правила сверяются с именем из SNI и DNS, а оно всегда в ASCII. Нормализации
//! UTS 46 нет: строчные буквы без составных знаков её не требуют.

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;
const PREFIX: &str = "xn--";

/// Имя в ASCII: метки с не-ASCII знаками — в `xn--…`; `None` — не кодируется.
pub fn to_ascii(domain: &str) -> Option<String> {
    domain
        .to_lowercase()
        .split('.')
        .map(|label| match label.is_ascii() {
            true => Some(label.to_owned()),
            false => encode(label).map(|code| format!("{PREFIX}{code}")),
        })
        .collect::<Option<Vec<_>>>()
        .map(|labels| labels.join("."))
}

/// Имя для показа: метки `xn--…` раскодированы; нераскодируемые — как есть.
pub fn to_unicode(domain: &str) -> String {
    domain
        .split('.')
        .map(|label| {
            label
                .strip_prefix(PREFIX)
                .and_then(decode)
                .unwrap_or_else(|| label.to_owned())
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn encode(label: &str) -> Option<String> {
    let input: Vec<u32> = label.chars().map(u32::from).collect();
    let mut output: String = label.chars().filter(char::is_ascii).collect();
    let basic = output.len();
    if basic > 0 {
        output.push('-');
    }

    let (mut n, mut delta, mut bias, mut handled) = (INITIAL_N, 0u32, INITIAL_BIAS, basic);
    while handled < input.len() {
        let next = input.iter().copied().filter(|&c| c >= n).min()?;
        let points = u32::try_from(handled).ok()? + 1;
        delta = delta.checked_add((next - n).checked_mul(points)?)?;
        n = next;
        for &c in &input {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c != n {
                continue;
            }
            let mut q = delta;
            let mut k = BASE;
            loop {
                let t = threshold(k, bias);
                if q < t {
                    break;
                }
                output.push(digit(t + (q - t) % (BASE - t)));
                q = (q - t) / (BASE - t);
                k += BASE;
            }
            output.push(digit(q));
            bias = adapt(delta, u32::try_from(handled).ok()? + 1, handled == basic);
            delta = 0;
            handled += 1;
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(output)
}

fn decode(code: &str) -> Option<String> {
    let (basic, extended) = code.rsplit_once('-').unwrap_or(("", code));
    if !basic.is_ascii() {
        return None;
    }
    let mut output: Vec<char> = basic.chars().collect();
    let (mut n, mut i, mut bias) = (INITIAL_N, 0u32, INITIAL_BIAS);
    let mut digits = extended.bytes().peekable();

    while digits.peek().is_some() {
        let start = i;
        let mut weight = 1u32;
        let mut k = BASE;
        loop {
            let d = value(digits.next()?)?;
            i = i.checked_add(d.checked_mul(weight)?)?;
            let t = threshold(k, bias);
            if d < t {
                break;
            }
            weight = weight.checked_mul(BASE - t)?;
            k += BASE;
        }
        let length = u32::try_from(output.len()).ok()? + 1;
        bias = adapt(i - start, length, start == 0);
        n = n.checked_add(i / length)?;
        i %= length;
        output.insert(usize::try_from(i).ok()?, char::from_u32(n)?);
        i += 1;
    }
    Some(output.into_iter().collect())
}

fn threshold(k: u32, bias: u32) -> u32 {
    k.saturating_sub(bias).clamp(TMIN, TMAX)
}

fn adapt(delta: u32, points: u32, first: bool) -> u32 {
    let mut delta = if first { delta / DAMP } else { delta / 2 };
    delta += delta / points;
    let mut k = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + (BASE - TMIN + 1) * delta / (delta + SKEW)
}

fn digit(d: u32) -> char {
    // 0–25 — буквы, 26–35 — цифры.
    let byte = if d < 26 {
        b'a' + d as u8
    } else {
        b'0' + (d - 26) as u8
    };
    char::from(byte)
}

fn value(byte: u8) -> Option<u32> {
    match byte {
        b'a'..=b'z' => Some(u32::from(byte - b'a')),
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 26),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Внешние векторы: зона `.рф` из корневой зоны IANA, `bücher` и
    /// `münchen` — из примеров IDNA; `пример.испытание` — тестовый домен IANA.
    #[test]
    fn known_names_encode_as_registered() {
        assert_eq!(to_ascii("рф").as_deref(), Some("xn--p1ai"));
        assert_eq!(
            to_ascii("Яндекс.РФ").as_deref(),
            Some("xn--d1acpjx3f.xn--p1ai")
        );
        assert_eq!(to_ascii("bücher.de").as_deref(), Some("xn--bcher-kva.de"));
        assert_eq!(to_ascii("münchen").as_deref(), Some("xn--mnchen-3ya"));
        assert_eq!(
            to_ascii("пример.испытание").as_deref(),
            Some("xn--e1afmkfd.xn--80akhbyknj4f")
        );
    }

    #[test]
    fn ascii_names_are_left_alone() {
        assert_eq!(to_ascii("Example.COM").as_deref(), Some("example.com"));
        assert_eq!(to_unicode("example.com"), "example.com");
    }

    #[test]
    fn encoded_names_decode_for_display() {
        assert_eq!(to_unicode("xn--d1acpjx3f.xn--p1ai"), "яндекс.рф");
        assert_eq!(to_unicode("xn--bcher-kva.de"), "bücher.de");
        assert_eq!(to_unicode("xn--mnchen-3ya"), "münchen");
    }

    #[test]
    fn broken_codes_are_shown_as_written() {
        assert_eq!(to_unicode("xn--!!"), "xn--!!");
    }
}
