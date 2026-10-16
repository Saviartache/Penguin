//! Адреса, подсети, домены, порты — разбор строки, введённой в одно поле.
//!
//! Проверка до сохранения: неверная подсеть в файле ломает весь набор правил.

/// Что за адрес ввели.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Подсеть или отдельный адрес.
    Network,
    /// Доменное имя.
    Domain,
    /// Порт или диапазон.
    Port,
}

/// Разобранная строка.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    /// Подсети и адреса.
    pub networks: Vec<String>,
    /// Домены.
    pub domains: Vec<String>,
    /// Порты.
    pub ports: Vec<u16>,
    /// Диапазоны портов, включительно.
    pub ranges: Vec<(u16, u16)>,
    /// Что не удалось опознать.
    pub unknown: Vec<String>,
}

/// Определяет вид; адрес проверяется раньше домена (`1.2.3.4` проходит под оба).
pub fn classify(value: &str) -> Option<Kind> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if value.parse::<ipnet::IpNet>().is_ok() || value.parse::<std::net::IpAddr>().is_ok() {
        return Some(Kind::Network);
    }
    if is_port_spec(value) {
        return Some(Kind::Port);
    }
    if is_domain(value) {
        return Some(Kind::Domain);
    }
    None
}

/// Значения строки; разделители любые: списки вставляют откуда придётся.
pub fn tokens(raw: &str) -> impl Iterator<Item = &str> {
    raw.split([',', ';', ' ', '\t', '\n', '\r'])
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// Отделяет порт от адреса: `host:443`, `[2001:db8::1]:443`. Голый IPv6 портом
/// не считается — двоеточия в нём свои.
pub fn split_port(token: &str) -> Option<(&str, &str)> {
    let (host, port) = match token.strip_prefix('[') {
        Some(rest) => {
            let (host, tail) = rest.split_once(']')?;
            (host, tail.strip_prefix(':')?)
        }
        None => token
            .rsplit_once(':')
            .filter(|(host, _)| !host.contains(':'))?,
    };
    (classify(port) == Some(Kind::Port) && !port.contains('-')).then_some((host, port))
}

/// Разбирает строку; разделители любые: списки вставляют откуда придётся.
pub fn parse(raw: &str) -> Parsed {
    let mut parsed = Parsed::default();

    for token in tokens(raw) {
        match classify(token) {
            Some(Kind::Network) => parsed.networks.push(token.to_owned()),
            Some(Kind::Domain) => parsed.domains.push(token.to_owned()),
            Some(Kind::Port) => match port_range(token) {
                Some((from, to)) if from == to => parsed.ports.push(from),
                Some(range) => parsed.ranges.push(range),
                None => parsed.unknown.push(token.to_owned()),
            },
            None => parsed.unknown.push(token.to_owned()),
        }
    }

    parsed
}

fn is_port_spec(value: &str) -> bool {
    let parse_port = |text: &str| text.trim().parse::<u16>().is_ok();

    match value.split_once('-') {
        Some((from, to)) => parse_port(from) && parse_port(to),
        None => parse_port(value),
    }
}

/// `443` или `8000-9000`; перевёрнутый диапазон — не диапазон.
fn port_range(token: &str) -> Option<(u16, u16)> {
    let (from, to) = token.split_once('-').unwrap_or((token, token));
    let (from, to) = (from.trim().parse().ok()?, to.trim().parse().ok()?);
    (from <= to).then_some((from, to))
}

fn is_domain(value: &str) -> bool {
    let value = value.trim_start_matches('.');

    !value.is_empty()
        && value.len() <= 253
        && value.contains('.')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_networks() {
        assert_eq!(classify("10.0.0.0/8"), Some(Kind::Network));
        assert_eq!(classify("192.168.1.1"), Some(Kind::Network));
        assert_eq!(classify("2001:db8::/32"), Some(Kind::Network));
    }

    #[test]
    fn an_address_wins_over_a_domain() {
        assert_eq!(classify("1.2.3.4"), Some(Kind::Network));
    }

    #[test]
    fn recognises_domains_and_ports() {
        assert_eq!(classify("example.com"), Some(Kind::Domain));
        assert_eq!(classify(".example.com"), Some(Kind::Domain));
        assert_eq!(classify("443"), Some(Kind::Port));
        assert_eq!(classify("8000-8100"), Some(Kind::Port));
    }

    #[test]
    fn rejects_nonsense() {
        assert_eq!(classify(""), None);
        assert_eq!(classify("без точки"), None);
        assert_eq!(classify("10.0.0.0/99"), None);
        assert_eq!(classify("99999"), None);
        // Однословное имя не разрешится через тоннель.
        assert_eq!(classify("localhost"), None);
    }

    #[test]
    fn one_field_takes_everything_at_once() {
        let parsed = parse("10.0.0.0/8, local.dev 445");

        assert_eq!(parsed.networks, ["10.0.0.0/8"]);
        assert_eq!(parsed.domains, ["local.dev"]);
        assert_eq!(parsed.ports, [445]);
        assert!(parsed.unknown.is_empty());
    }

    #[test]
    fn separators_are_whatever_was_pasted() {
        assert_eq!(
            parse("a.com,b.com;c.com\nd.com\te.com f.com").domains.len(),
            6
        );
    }

    #[test]
    fn nonsense_is_reported_not_swallowed() {
        let parsed = parse("example.com  ??? 10.0.0.0/99");
        assert_eq!(parsed.domains, ["example.com"]);
        assert_eq!(parsed.unknown, ["???", "10.0.0.0/99"]);
    }

    #[test]
    fn port_ranges_stay_ranges() {
        assert_eq!(parse("27000-27100").ranges, [(27000, 27100)]);
        assert_eq!(parse("443-443").ports, [443]);
        assert_eq!(parse("500-100").unknown, ["500-100"]);
    }

    #[test]
    fn a_port_is_split_off_an_address() {
        assert_eq!(
            split_port("192.168.1.0:30000"),
            Some(("192.168.1.0", "30000"))
        );
        assert_eq!(split_port("google.com:443"), Some(("google.com", "443")));
        assert_eq!(
            split_port("[2001:db8::1]:443"),
            Some(("2001:db8::1", "443"))
        );
        assert_eq!(split_port("2001:db8::1"), None);
        assert_eq!(split_port("google.com"), None);
        assert_eq!(split_port("google.com:http"), None);
    }

    #[test]
    fn an_empty_parse_is_empty() {
        assert_eq!(parse(""), Parsed::default());
        assert_eq!(parse("443").ports, [443]);
    }
}
