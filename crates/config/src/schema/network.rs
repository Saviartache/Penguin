//! MTU, имя TUN-адаптера, IPv6, kill switch.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Сетевые настройки клиента.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    /// Виртуальный адаптер.
    pub tun: TunConfig,
    /// Локальный SOCKS5. Работает без прав администратора и без адаптера.
    pub socks: Option<InboundConfig>,
    /// Локальный HTTP-прокси.
    pub http: Option<InboundConfig>,
    /// При падении тоннеля блокировать трафик, а не выпускать его напрямую.
    pub kill_switch: bool,
    /// Разрешить обмен с локальной сетью мимо тоннеля.
    pub allow_lan: bool,
    /// Забирать маршрут по умолчанию; выключено — в тоннель идёт только трафик
    /// локального прокси (в отличие от [`TunnelMode::Direct`]).
    ///
    /// [`TunnelMode::Direct`]: crate::schema::routing::TunnelMode::Direct
    pub capture_default_route: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            tun: TunConfig::default(),
            socks: None,
            http: None,
            kill_switch: true,
            allow_lan: true,
            capture_default_route: true,
        }
    }
}

/// Виртуальный сетевой адаптер.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TunConfig {
    /// Имя адаптера в системе.
    pub name: String,
    /// Наибольший размер пакета; в сеть не уходит, поэтому 1500, а не 1280.
    pub mtu: u16,
    /// Адрес адаптера в служебной подсети.
    pub ipv4: Ipv4Addr,
    /// Длина префикса IPv4.
    pub ipv4_prefix: u8,
    /// Адрес IPv6, если он включён.
    pub ipv6: Ipv6Addr,
    /// Длина префикса IPv6.
    pub ipv6_prefix: u8,
    /// Пропускать IPv6 через тоннель; выключено — иначе утечка мимо правил.
    pub ipv6_enabled: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "Penguin".to_owned(),
            mtu: 1500,
            ipv4: Ipv4Addr::new(198, 18, 0, 1),
            ipv4_prefix: 16,
            ipv6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            ipv6_prefix: 64,
            ipv6_enabled: false,
        }
    }
}

/// Локальная точка входа: SOCKS5 или HTTP.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundConfig {
    /// Где слушать.
    pub listen: SocketAddr,
    /// Логин и пароль; не-localhost без пароля отвергает `validate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<InboundAuth>,
}

/// Логин и пароль локальной точки входа.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundAuth {
    /// Имя пользователя.
    pub username: String,
    /// Пароль.
    pub password: String,
}
