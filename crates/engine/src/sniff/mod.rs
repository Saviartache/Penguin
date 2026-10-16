//! Имя хоста из первых байт соединения (режим TUN, приложение пришло по IP).
//! Дополняет обратное отображение fake-IP; поток при этом не меняется.

pub mod http;
pub mod quic;
pub mod tls;

use std::time::Duration;

use penguin_core::address::Address;
use penguin_core::network::Network;

/// Сколько ждать первых байт (клиент может ждать приветствия сервера).
pub const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);

/// Сколько байт достаточно для опознания (имя лежит в начале ClientHello).
pub const SNIFF_LIMIT: usize = 4 * 1024;

/// Пытается опознать имя хоста в первых байтах.
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
        assert!(sniff(Network::Tcp, &[0u8; 64]).is_none());
        assert!(sniff(Network::Udp, &[0u8; 64]).is_none());
    }

    #[test]
    fn name_is_normalised() {
        let request = b"GET / HTTP/1.1\r\nHost: Example.COM\r\n\r\n";
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
