//! Миграция на схему версии 2: MTU адаптера.
//!
//! Версия 1 ставила 1280 — нижнюю границу MTU для IPv6, с запасом под
//! накладные расходы QUIC. Запас оказался лишним: клиент завершает TCP у себя
//! и передаёт наружу поток байтов, а не пакеты. Этот размер **не уходит в
//! сеть** и ограничивает только участок между приложением и стеком внутри
//! машины.
//!
//! Ценой была пятая часть пропускной способности: каждый пакет проходит весь
//! цикл опроса, а при 1280 их на тот же объём нужно на пятую часть больше.
//!
//! Меняется только то самое значение. Поставленное человеком остаётся: он мог
//! опустить MTU намеренно — например, под канал с меньшим размером пакета.

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
        // Человек мог опустить MTU намеренно — под канал, который больше не
        // пропускает. Переписать это значит сломать ему тоннель.
        let mut config = RootConfig {
            version: 1,
            ..RootConfig::default()
        };
        config.network.tun.mtu = 1200;

        let migrated = from_v1(config);
        assert_eq!(migrated.network.tun.mtu, 1200);
    }
}
