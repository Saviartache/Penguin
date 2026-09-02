//! Пакет как буфер с временем жизни. Аллокация на пакет недопустима.
//!
//! На гигабите это порядка восьмидесяти тысяч пакетов в секунду; выделять под
//! каждый память значило бы отдать заметную долю процессора распределителю.
//!
//! Здесь лежит то немногое, что нужно знать о пакете **до** разбора: версия
//! протокола. По ней стек решает, куда его отдавать, а адаптер — не пришёл ли
//! мусор.

/// Версия протокола сети в первом байте пакета.
///
/// `None` — буфер пуст или версия не та, что мы понимаем.
pub fn ip_version(packet: &[u8]) -> Option<u8> {
    let first = *packet.first()?;
    match first >> 4 {
        version @ (4 | 6) => Some(version),
        _ => None,
    }
}

/// Это пакет IPv4.
pub fn is_ipv4(packet: &[u8]) -> bool {
    ip_version(packet) == Some(4)
}

/// Это пакет IPv6.
pub fn is_ipv6(packet: &[u8]) -> bool {
    ip_version(packet) == Some(6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_version_nibble() {
        // Версия лежит в старших четырёх битах первого байта.
        assert_eq!(ip_version(&[0x45, 0, 0, 20]), Some(4));
        assert_eq!(ip_version(&[0x60, 0, 0, 0]), Some(6));
    }

    #[test]
    fn rejects_empty_and_garbage() {
        assert_eq!(ip_version(&[]), None);
        // Восьмёрка в старших битах — не версия IP; такое приходит, когда в
        // кольцо попал мусор.
        assert_eq!(ip_version(&[0x80]), None);
    }

    #[test]
    fn helpers_agree_with_the_version() {
        assert!(is_ipv4(&[0x45]));
        assert!(!is_ipv6(&[0x45]));
        assert!(is_ipv6(&[0x60]));
        assert!(!is_ipv4(&[0x60]));
    }
}
