//! Чтение имени хоста из первых байт соединения. Без него правила по доменам
//! не работают, когда приложение ходит по IP.
//!
//! Задача возникает только в режиме TUN. Приложение, настроенное на прокси,
//! отдаёт имя само; приложение, которого перехватили на уровне пакетов, уже
//! разрешило имя и открывает соединение к адресу — имя из системы исчезло.
//!
//! Два способа его вернуть, и они дополняют друг друга:
//!
//! | Способ | Когда работает |
//! |---|---|
//! | обратное отображение fake-IP | приложение спрашивало имя у нашего DNS |
//! | опознание в потоке (этот модуль) | всегда, если протокол несёт имя |
//!
//! Разбирается ровно столько, сколько нужно для имени. Это не реализация TLS
//! и не разбор HTTP: байты читаются, имя достаётся, поток идёт дальше
//! нетронутым.

pub mod http;
pub mod quic;
pub mod tls;

use std::time::Duration;

use penguin_core::address::Address;
use penguin_core::network::Network;

/// Сколько ждать первых байт.
///
/// Приложение может открыть соединение и молчать — так делает, например,
/// клиент, ждущий приветствия сервера. Держать его дольше нельзя: соединение
/// уже открыто, а данные не идут ни в одну сторону.
pub const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);

/// Сколько байт достаточно для опознания.
///
/// ClientHello с длинным списком расширений доходит до нескольких килобайт;
/// больше читать незачем — имя лежит в начале.
pub const SNIFF_LIMIT: usize = 4 * 1024;

/// Пытается опознать имя хоста в первых байтах.
///
/// Порядок проверок — от частого к редкому: почти весь трафик сегодня TLS.
pub fn sniff(network: Network, data: &[u8]) -> Option<Address> {
    let host = match network {
        Network::Tcp => tls::extract_sni(data).or_else(|| http::extract_host(data)),
        Network::Udp => quic::extract_sni(data),
    }?;

    Some(Address::domain(host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_http() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            sniff(Network::Tcp, request),
            Some(Address::domain("example.com"))
        );
    }

    #[test]
    fn returns_nothing_for_unknown_protocols() {
        // Двоичный поток без имени — обычное дело: SSH, свои протоколы,
        // уже установленное соединение. Имени просто нет.
        assert!(sniff(Network::Tcp, &[0u8; 64]).is_none());
        assert!(sniff(Network::Udp, &[0u8; 64]).is_none());
    }

    #[test]
    fn name_is_normalised() {
        let request = b"GET / HTTP/1.1\r\nHost: Example.COM\r\n\r\n";
        // Сопоставители сравнивают нормализованные имена; вернуть сюда
        // исходный регистр значило бы, что правило по домену не сработает.
        assert_eq!(
            sniff(Network::Tcp, request),
            Some(Address::domain("example.com"))
        );
    }

    #[test]
    fn limits_are_sane() {
        assert!(
            SNIFF_TIMEOUT <= Duration::from_secs(1),
            "долгое ожидание задержит соединение"
        );
        const {
            assert!(SNIFF_LIMIT >= 1024, "ClientHello бывает длиннее килобайта")
        };
    }
}
