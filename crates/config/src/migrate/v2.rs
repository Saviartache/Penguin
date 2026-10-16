//! Миграция на схему версии 2: MTU адаптера.
//!
//! Умолчание 1280 поднимается до 1500 (MTU в сеть не уходит); заданное вручную не трогается.

use crate::schema::RootConfig;

/// Прежнее умолчание, которое и надо поднять.
const OLD_DEFAULT: u16 = 1280;

/// Нынешнее умолчание.
const NEW_DEFAULT: u16 = 1500;

/// Поднимает файл версии 1 до версии 2.
pub fn from_v1(mut config: RootConfig) -> RootConfig {
    if config.network.tun.mtu == OLD_DEFAULT {
        config.network.tun.mtu = NEW_DEFAULT;
    }
    config.version = 2;
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_old_default_is_raised() {
        let config = RootConfig {
            version: 1,
            ..RootConfig::default()
        };
        let migrated = from_v1(RootConfig {
            network: crate::schema::network::NetworkConfig {
                tun: crate::schema::network::TunConfig {
                    mtu: OLD_DEFAULT,
                    ..config.network.tun.clone()
                },
                ..config.network.clone()
            },
            ..config
        });

        assert_eq!(migrated.network.tun.mtu, NEW_DEFAULT);
        assert_eq!(migrated.version, 2);
    }

    #[test]
    fn a_deliberate_value_is_left_alone() {
        let mut config = RootConfig {
            version: 1,
            ..RootConfig::default()
        };
        config.network.tun.mtu = 1200;

        let migrated = from_v1(config);
        assert_eq!(migrated.network.tun.mtu, 1200);
    }
}
