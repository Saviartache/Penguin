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
    ///
    /// Включено: иначе перестают работать принтер, сетевые диски и всё
    /// остальное в квартире, и первое, что делает пользователь, — выключает
    /// клиент целиком.
    pub allow_lan: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            tun: TunConfig::default(),
            socks: None,
            http: None,
            kill_switch: true,
            allow_lan: true,
        }
    }
}

/// Виртуальный сетевой адаптер.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TunConfig {
    /// Имя адаптера в системе.
    pub name: String,
    /// Наибольший размер пакета.
    ///
    /// Обычные 1500, а не осторожные 1280, и вот почему: этот размер **не
    /// уходит в сеть**. Клиент завершает TCP у себя и передаёт наружу поток
    /// байтов по hysteria2, а не пакеты — запас под накладные расходы QUIC
    /// здесь брать не с чего и не для чего.
    ///
    /// Он ограничивает только участок между приложением и стеком, внутри
    /// машины. Меньший размер означает больше пакетов на тот же объём, а
    /// каждый пакет проходит весь цикл опроса: 1280 отнимало пятую часть
    /// пропускной способности ни за что.
    pub mtu: u16,
    /// Адрес адаптера в служебной подсети.
    pub ipv4: Ipv4Addr,
    /// Длина префикса IPv4.
    pub ipv4_prefix: u8,
    /// Адрес IPv6, если он включён.
    pub ipv6: Ipv6Addr,
    /// Длина префикса IPv6.
    pub ipv6_prefix: u8,
    /// Пропускать IPv6 через тоннель.
    ///
    /// Выключено: пока протокол не проверен на IPv6, включённый IPv6 — это
    /// готовая утечка мимо всех правил. `platform::firewall` его на время
    /// сеанса гасит.
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
    /// Логин и пароль, если нужны.
    ///
    /// Прокси, открытый на `0.0.0.0` без пароля, — открытый прокси для всей
    /// сети; проверка в `validate` про это напоминает.
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
