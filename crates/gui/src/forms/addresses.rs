//! Адреса, подсети, домены, порты — разбор того, что вписали одной строкой.
//!
//! Одно поле на все четыре вида намеренно. Человек знает, что хочет пустить
//! мимо тоннеля `10.0.0.0/8`, `local.dev` и `445`; к какому виду условия это
//! относится, он знать не обязан. Четыре отдельных поля заставляли бы его
//! сначала классифицировать, а потом вводить.
//!
//! Проверка идёт **до** сохранения: неверная подсеть, попавшая в файл, ломает
//! весь набор правил целиком — маршрутизатор отказывается его собирать, и
//! трафик уходит по умолчанию режима.

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
    /// Что не удалось опознать.
    pub unknown: Vec<String>,
}

impl Parsed {
    /// Есть ли хоть одно понятое значение.
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty() && self.domains.is_empty() && self.ports.is_empty()
    }
}

/// Определяет, что это за строка.
///
/// Порядок проверок важен: `1.2.3.4` — это адрес, а не домен, хотя формально
/// проходит и под домен.
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

/// Разбирает строку целиком.
///
/// Разделители — запятая, точка с запятой, пробел и перевод строки: люди
/// вставляют списки откуда придётся, и требовать одного разделителя значит
/// требовать ручной правки вставленного.
pub fn parse(raw: &str) -> Parsed {
    let mut parsed = Parsed::default();

    for token in raw.split([',', ';', ' ', '\t', '\n', '\r']) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        match classify(token) {
            Some(Kind::Network) => parsed.networks.push(token.to_owned()),
            Some(Kind::Domain) => parsed.domains.push(token.to_owned()),
            Some(Kind::Port) => match token.parse::<u16>() {
                Ok(port) => parsed.ports.push(port),
                Err(_) => parsed.ports.extend(expand_range(token)),
            },
            None => parsed.unknown.push(token.to_owned()),
        }
    }

    parsed
}

/// Похоже ли на порт или диапазон портов.
fn is_port_spec(value: &str) -> bool {
    let parse_port = |text: &str| text.trim().parse::<u16>().is_ok();

    match value.split_once('-') {
        Some((from, to)) => parse_port(from) && parse_port(to),
        None => parse_port(value),
    }
}

/// Похоже ли на доменное имя.
fn is_domain(value: &str) -> bool {
    let value = value.trim_start_matches('.');

    !value.is_empty()
        && value.len() <= 253
        && value.contains('.')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Разворачивает `8000-8010` в перечень портов.
///
/// Только для коротких диапазонов: «8000-9000» перечнем — это тысяча значений
/// в файле настроек.
fn expand_range(token: &str) -> Vec<u16> {
    /// Сколько портов ещё разумно перечислить.
    const MAX_SPAN: u32 = 64;

    let Some((from, to)) = token.split_once('-') else {
        return Vec::new();
    };
    let (Ok(from), Ok(to)) = (from.trim().parse::<u16>(), to.trim().parse::<u16>()) else {
        return Vec::new();
    };
    if from > to || u32::from(to - from) > MAX_SPAN {
        return Vec::new();
    }

    (from..=to).collect()
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
        // `1.2.3.4` формально проходит и под домен; спутать их означало бы
        // отправить адрес в правило по именам, где он никогда не совпадёт.
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
        // Неверная запись, попавшая в файл, ломает весь набор правил.
        assert_eq!(classify(""), None);
        assert_eq!(classify("без точки"), None);
        assert_eq!(classify("10.0.0.0/99"), None);
        assert_eq!(classify("99999"), None);
        // Однословное имя — либо опечатка, либо локальное имя, которое всё
        // равно не разрешится через тоннель.
        assert_eq!(classify("localhost"), None);
    }

    #[test]
    fn one_field_takes_everything_at_once() {
        // Ровно то, ради чего поле одно.
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
        // Молча выброшенный кусок означает правило не о том, о чём думали.
        let parsed = parse("example.com  ??? 10.0.0.0/99");
        assert_eq!(parsed.domains, ["example.com"]);
        assert_eq!(parsed.unknown, ["???", "10.0.0.0/99"]);
    }

    #[test]
    fn short_port_ranges_expand_and_huge_ones_do_not() {
        assert_eq!(parse("8000-8003").ports, [8000, 8001, 8002, 8003]);
        // «8000-9000» перечнем — тысяча значений в файле настроек.
        assert!(parse("8000-9000").ports.is_empty());
        assert!(parse("500-100").ports.is_empty());
    }

    #[test]
    fn an_empty_parse_is_empty() {
        assert!(parse("").is_empty());
        assert!(!parse("443").is_empty());
    }
}
