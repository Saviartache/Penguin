//! Имена сетей без обращения к системе.

const MAX_NAME: usize = 128;
const DIGITS: [(u32, &str); 13] = [
    (1000, "M"),
    (900, "CM"),
    (500, "D"),
    (400, "CD"),
    (100, "C"),
    (90, "XC"),
    (50, "L"),
    (40, "XL"),
    (10, "X"),
    (9, "IX"),
    (5, "V"),
    (4, "IV"),
    (1, "I"),
];

pub(super) fn next(base: &str, current: &str, others: &[String]) -> Option<String> {
    if current
        .strip_prefix(base)
        .and_then(|s| s.strip_prefix(' '))
        .and_then(roman_index)
        .is_some()
    {
        return Some(current.to_owned());
    }
    let previous = others
        .iter()
        .filter_map(|name| index(base, name))
        .max()
        .unwrap_or(0);
    let number = index(base, current)
        .unwrap_or(1)
        .max(previous.checked_add(1)?);
    let name = format!("{base} {}", roman(number)?);
    (name.encode_utf16().count() <= MAX_NAME).then_some(name)
}

fn index(base: &str, name: &str) -> Option<u32> {
    if name == base {
        return Some(1);
    }
    let suffix = name.strip_prefix(base)?.strip_prefix(' ')?;
    if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) {
        return suffix.parse().ok().filter(|n| *n > 0);
    }
    roman_index(suffix)
}

fn roman(mut number: u32) -> Option<String> {
    if number == 0 || number / 1000 > MAX_NAME as u32 {
        return None;
    }
    let mut text = String::new();
    for (value, digit) in DIGITS {
        while number >= value {
            text.push_str(digit);
            number -= value;
        }
    }
    Some(text)
}

fn roman_index(text: &str) -> Option<u32> {
    let mut rest = text;
    let mut number = 0u32;
    for (value, digit) in DIGITS {
        while let Some(tail) = rest.strip_prefix(digit) {
            number = number.checked_add(value)?;
            rest = tail;
        }
    }
    (rest.is_empty() && roman(number).as_deref() == Some(text)).then_some(number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_names_become_roman() {
        for (current, expected) in [
            ("Penguin", "Penguin I"),
            ("Penguin 1", "Penguin I"),
            ("Penguin 4", "Penguin IV"),
            ("Penguin 17", "Penguin XVII"),
            ("Penguin 49", "Penguin XLIX"),
            ("Penguin 1994", "Penguin MCMXCIV"),
        ] {
            assert_eq!(next("Penguin", current, &[]).as_deref(), Some(expected));
        }
    }

    #[test]
    fn sequence_continues_across_both_number_formats() {
        let names = [
            "Penguin",
            "Penguin 16",
            "Penguin XVII",
            "Other 999",
            "Penguin VPN",
        ]
        .map(str::to_owned);
        assert_eq!(
            next("Penguin", "Penguin 2", &names).as_deref(),
            Some("Penguin XVIII")
        );
        assert_eq!(
            next("Penguin", "Penguin XVIII", &names).as_deref(),
            Some("Penguin XVIII")
        );
    }

    #[test]
    fn custom_adapter_names_are_supported() {
        assert_eq!(
            next("VPN дома", "Network 3", &[]).as_deref(),
            Some("VPN дома I")
        );
    }

    #[test]
    fn malformed_suffixes_are_not_part_of_the_sequence() {
        for name in [
            "Penguin 0",
            "Penguin IIII",
            "Penguin IC",
            "Penguin ix",
            "Penguin ",
        ] {
            assert_eq!(index("Penguin", name), None);
        }
    }

    #[test]
    fn oversized_names_and_numbers_fail_without_large_allocations() {
        assert!(next("Penguin", "Penguin 4294967295", &[]).is_none());
        assert!(next(&"x".repeat(128), "Network", &[]).is_none());
    }
}
