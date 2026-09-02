//! Параметры стека: адреса, MTU, размеры буферов, таймауты.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Настройки пользовательского стека.
#[derive(Debug, Clone)]
pub struct StackConfig {
    /// Адрес адаптера и длина префикса.
    pub ipv4: (Ipv4Addr, u8),
    /// Адрес IPv6, если он включён.
    pub ipv6: Option<(Ipv6Addr, u8)>,
    /// Наибольший размер пакета.
    pub mtu: u16,
    /// Размер буфера приёма у одного TCP-сокета.
    pub tcp_rx_buffer: usize,
    /// Размер буфера отправки.
    pub tcp_tx_buffer: usize,
}

impl StackConfig {
    /// Настройки из конфигурации адаптера.
    pub fn from_tun(config: &penguin_tun::TunConfig) -> Self {
        Self {
            ipv4: config.ipv4,
            ipv6: config.ipv6,
            mtu: config.mtu,
            ..Self::default()
        }
    }
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            ipv4: (Ipv4Addr::new(198, 18, 0, 1), 16),
            ipv6: None,
            mtu: 1500,
            // Буфер должен вмещать произведение полосы на задержку внутри
            // машины, а не в сети: приложение пишет в тоннель, и задержка тут
            // микросекундная. Шестьдесят четыре килобайта — обычное окно TCP,
            // и умножать его на число соединений незачем: их бывают сотни.
            tcp_rx_buffer: 64 * 1024,
            tcp_tx_buffer: 64 * 1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherits_the_adapter_settings() {
        let tun = penguin_tun::TunConfig {
            mtu: 1400,
            ipv6: Some((Ipv6Addr::LOCALHOST, 64)),
            ..penguin_tun::TunConfig::default()
        };

        let stack = StackConfig::from_tun(&tun);
        assert_eq!(stack.mtu, 1400);
        assert_eq!(stack.ipv4, tun.ipv4);
        assert!(stack.ipv6.is_some());
    }

    #[test]
    fn buffers_are_not_absurd() {
        // Буферы умножаются на число соединений; их бывают сотни.
        let config = StackConfig::default();
        assert!(config.tcp_rx_buffer >= 16 * 1024);
        assert!(config.tcp_rx_buffer <= 1024 * 1024);
    }
}
