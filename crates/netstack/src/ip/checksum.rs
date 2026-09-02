//! Контрольные суммы IPv4, TCP, UDP.
//!
//! Одна и та же арифметика на все три: сумма шестнадцатибитных слов с
//! переносом обратно в младшие разряды, затем побитовое отрицание
//! (RFC 1071). Разница только в том, что суммируется.
//!
//! Считать их приходится самим, потому что пакеты для приложения мы
//! собираем сами: система примет только пакет с верной суммой, а
//! неверный молча выбросит — без ошибки и без следа в журнале.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Складывает байты как шестнадцатибитные слова с переносом.
///
/// Промежуточная сумма в `u32`: переносы копятся в старшей половине и
/// сворачиваются один раз в конце.
pub fn sum(data: &[u8]) -> u32 {
    let mut total = 0u32;
    let mut chunks = data.chunks_exact(2);

    for chunk in &mut chunks {
        total += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    // Нечётный хвост дополняется нулём справа, а не слева.
    if let [last] = chunks.remainder() {
        total += u32::from(u16::from_be_bytes([*last, 0]));
    }
    total
}

/// Сворачивает переносы и отрицает — готовая контрольная сумма.
pub fn finish(mut total: u32) -> u16 {
    while total >> 16 != 0 {
        total = (total & 0xFFFF) + (total >> 16);
    }
    !(total as u16)
}

/// Контрольная сумма заголовка IPv4.
///
/// Считается по заголовку, в котором поле суммы обнулено.
pub fn ipv4_header(header: &[u8]) -> u16 {
    let mut total = sum(&header[..10]);
    // Байты 10–11 — само поле суммы; при подсчёте оно считается нулевым.
    total += sum(&header[12..]);
    finish(total)
}

/// Псевдозаголовок IPv4 для TCP и UDP.
///
/// В сумму входят адреса, протокол и длина — благодаря этому подменённый
/// адрес ломает сумму, и пакет отбрасывается.
pub fn pseudo_v4(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, length: u16) -> u32 {
    let mut total = sum(&source.octets()) + sum(&destination.octets());
    total += u32::from(protocol);
    total += u32::from(length);
    total
}

/// Псевдозаголовок IPv6.
pub fn pseudo_v6(source: Ipv6Addr, destination: Ipv6Addr, protocol: u8, length: u32) -> u32 {
    let mut total = sum(&source.octets()) + sum(&destination.octets());
    total += length >> 16;
    total += length & 0xFFFF;
    total += u32::from(protocol);
    total
}

/// Контрольная сумма UDP поверх IPv4.
///
/// Нулевой результат заменяется на `0xFFFF`: ноль в этом поле означает
/// «сумма не считалась», и настоящий ноль пришлось бы отличать от отказа.
pub fn udp_v4(source: Ipv4Addr, destination: Ipv4Addr, datagram: &[u8]) -> u16 {
    let total = pseudo_v4(source, destination, 17, datagram.len() as u16) + sum(datagram);
    match finish(total) {
        0 => 0xFFFF,
        value => value,
    }
}

/// Контрольная сумма UDP поверх IPv6.
///
/// В IPv6 сумма обязательна: заголовка с собственной суммой там нет.
pub fn udp_v6(source: Ipv6Addr, destination: Ipv6Addr, datagram: &[u8]) -> u16 {
    let total = pseudo_v6(source, destination, 17, datagram.len() as u32) + sum(datagram);
    match finish(total) {
        0 => 0xFFFF,
        value => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_1071_example() {
        // Пример из RFC 1071, §3: слова 0001 f203 f4f5 f6f7 дают 220d.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(finish(sum(&data)), 0x220d);
    }

    #[test]
    fn odd_length_pads_on_the_right() {
        // Дополнение слева дало бы другое число и неверную сумму на каждом
        // пакете нечётной длины.
        assert_eq!(sum(&[0x12]), 0x1200);
        assert_eq!(sum(&[0x12, 0x00]), 0x1200);
    }

    #[test]
    fn verifies_a_real_ipv4_header() {
        // Заголовок из примера в учебниках: сумма считается верной, если
        // повторный подсчёт вместе с полем даёт ноль.
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(ipv4_header(&header), 0xb861);
        // Проверка целиком: сумма по всему заголовку должна свернуться в ноль.
        assert_eq!(finish(sum(&header)), 0);
    }

    #[test]
    fn udp_checksum_never_reports_zero() {
        // Ноль в поле означает «не считалась»; настоящий ноль обязан
        // превратиться в 0xFFFF, иначе получатель решит, что суммы нет.
        let source = Ipv4Addr::new(1, 2, 3, 4);
        let destination = Ipv4Addr::new(5, 6, 7, 8);
        for length in 0..200usize {
            let datagram = vec![0x5A; length];
            assert_ne!(udp_v4(source, destination, &datagram), 0);
        }
    }

    #[test]
    fn udp_checksum_detects_address_substitution() {
        // Адрес входит в псевдозаголовок; подменённый ломает сумму.
        let datagram = [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];
        let original = udp_v4(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            &datagram,
        );
        let substituted = udp_v4(
            Ipv4Addr::new(1, 2, 3, 5),
            Ipv4Addr::new(5, 6, 7, 8),
            &datagram,
        );
        assert_ne!(original, substituted);
    }

    #[test]
    fn carries_fold_correctly() {
        // Данные, копящие перенос в старшей половине `u32` много раз: без
        // полного сворачивания сумма выйдет неверной, а пакет с неверной
        // суммой система молча выбросит.
        let data: Vec<u8> = (0..4096).map(|byte| (byte % 251) as u8).collect();
        let total = sum(&data);
        assert_ne!(total >> 16, 0, "перенос не накопился — сворачивать нечего");

        // Проверка со стороны получателя: сумма данных **вместе с самой
        // контрольной суммой** обязана дать ноль. Именно так пакет и
        // проверяют, и именно это ломает несвёрнутый перенос.
        let checksum = finish(total);
        assert_eq!(finish(total + u32::from(checksum)), 0);
    }

    #[test]
    fn v6_pseudo_header_uses_full_length() {
        // Длина в IPv6 — тридцать два разряда, и старшая половина должна
        // попасть в сумму.
        let source = Ipv6Addr::LOCALHOST;
        let destination = Ipv6Addr::LOCALHOST;
        let short = pseudo_v6(source, destination, 17, 0x0000_0010);
        let long = pseudo_v6(source, destination, 17, 0x0001_0010);
        assert_ne!(short, long);
    }
}
