//! Параметры адаптера: имя, MTU, адреса, маршруты, DNS.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Настройки виртуального адаптера.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Имя адаптера в системе.
    pub name: String,
    /// Наибольший размер пакета.
    pub mtu: u16,
    /// Адрес адаптера IPv4 и длина префикса.
    pub ipv4: (Ipv4Addr, u8),
    /// Адрес IPv6, если он включён.
    pub ipv6: Option<(Ipv6Addr, u8)>,
    /// Размер кольцевого буфера драйвера.
    pub ring_capacity: u32,
}

impl TunConfig {
    /// Настройки из конфигурации клиента.
    pub fn from_schema(config: &penguin_config::schema::network::TunConfig) -> Self {
        Self {
            name: config.name.clone(),
            mtu: config.mtu,
            ipv4: (config.ipv4, config.ipv4_prefix),
            ipv6: config
                .ipv6_enabled
                .then_some((config.ipv6, config.ipv6_prefix)),
            ring_capacity: DEFAULT_RING_CAPACITY,
        }
    }

    /// Маска подсети IPv4.
    pub fn ipv4_netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(prefix_to_mask_v4(self.ipv4.1))
    }

    /// Адрес адаптера.
    pub fn address(&self) -> IpAddr {
        IpAddr::V4(self.ipv4.0)
    }

    /// Подсеть адаптера в виде `198.18.0.0/15`.
    ///
    /// По ней kill switch опознаёт трафик тоннеля: пакет, ушедший в адаптер,
    /// получает адрес источника отсюда, куда бы ни шёл дальше. Ошибка здесь
    /// означает запрет, под который попадает и сам тоннель.
    pub fn subnet(&self) -> String {
        let (address, prefix) = self.ipv4;
        let network = Ipv4Addr::from(u32::from(address) & prefix_to_mask_v4(prefix));
        format!("{network}/{prefix}")
    }

    /// Шлюз внутри служебной подсети.
    ///
    /// Системе нужен адрес следующего узла для маршрута по умолчанию. За
    /// адаптером никого нет, поэтому шлюзом назначается он сам: пакеты всё
    /// равно приходят к нам.
    pub fn gateway(&self) -> IpAddr {
        IpAddr::V4(self.ipv4.0)
    }
}

/// Размер кольца драйвера по умолчанию.
///
/// Четыре мегабайта — примерно три тысячи пакетов по MTU. Меньше означает
/// потерю пакетов на всплесках трафика, больше — память, которая почти всегда
/// пустует.
pub const DEFAULT_RING_CAPACITY: u32 = 4 * 1024 * 1024;

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "Penguin".to_owned(),
            mtu: 1500,
            // `198.18.0.0/15` отведена под тестирование производительности
            // сетей (RFC 2544) и в настоящем трафике не встречается — значит,
            // служебная подсеть ни с чем не столкнётся.
            ipv4: (Ipv4Addr::new(198, 18, 0, 1), 16),
            ipv6: None,
            ring_capacity: DEFAULT_RING_CAPACITY,
        }
    }
}

/// Превращает длину префикса в маску.
fn prefix_to_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        return 0;
    }
    // Сдвиг на 32 у 32-битного числа не определён, поэтому нулевой префикс
    // обработан отдельно выше.
    u32::MAX << (32 - prefix.min(32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_prefix_to_mask() {
        assert_eq!(
            Ipv4Addr::from(prefix_to_mask_v4(24)),
            Ipv4Addr::new(255, 255, 255, 0)
        );
        assert_eq!(
            Ipv4Addr::from(prefix_to_mask_v4(16)),
            Ipv4Addr::new(255, 255, 0, 0)
        );
        assert_eq!(
            Ipv4Addr::from(prefix_to_mask_v4(32)),
            Ipv4Addr::new(255, 255, 255, 255)
        );
    }

    #[test]
    fn zero_prefix_does_not_overflow_the_shift() {
        // Сдвиг на 32 у 32-битного числа — неопределённое поведение, и в
        // отладочной сборке это паника.
        assert_eq!(prefix_to_mask_v4(0), 0);
    }

    #[test]
    fn oversized_prefix_is_clamped() {
        assert_eq!(prefix_to_mask_v4(200), u32::MAX);
    }

    #[test]
    fn default_uses_a_reserved_subnet() {
        // Служебная подсеть не должна столкнуться с настоящей сетью
        // пользователя.
        let config = TunConfig::default();
        assert_eq!(config.ipv4.0.octets()[0], 198);
        assert_eq!(config.ipv4.0.octets()[1], 18);
    }

    #[test]
    fn reads_the_client_config() {
        let mut schema = penguin_config::schema::network::TunConfig {
            name: "Тест".to_owned(),
            ipv6_enabled: true,
            ..penguin_config::schema::network::TunConfig::default()
        };

        let config = TunConfig::from_schema(&schema);
        assert_eq!(config.name, "Тест");
        assert!(config.ipv6.is_some());

        schema.ipv6_enabled = false;
        // Выключенный IPv6 не должен просочиться в адаптер: иначе получится
        // готовая утечка мимо всех правил.
        assert!(TunConfig::from_schema(&schema).ipv6.is_none());
    }

    #[test]
    fn the_subnet_is_the_network_not_the_address() {
        // Адрес адаптера — 198.18.0.1, а подсеть начинается с нуля. Разрешение
        // по адресу вместо подсети пропустило бы только его собственный
        // трафик, и kill switch перекрыл бы тоннель.
        let config = TunConfig {
            ipv4: (Ipv4Addr::new(198, 18, 0, 1), 15),
            ..TunConfig::default()
        };
        assert_eq!(config.subnet(), "198.18.0.0/15");
    }

    #[test]
    fn a_full_prefix_keeps_the_address() {
        let config = TunConfig {
            ipv4: (Ipv4Addr::new(10, 1, 2, 3), 32),
            ..TunConfig::default()
        };
        assert_eq!(config.subnet(), "10.1.2.3/32");
    }
}
