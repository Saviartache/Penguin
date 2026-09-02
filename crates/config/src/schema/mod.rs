//! `RootConfig` — корень файла настроек.

pub mod app;
pub mod dns;
pub mod network;
pub mod outbound;
pub mod profile;
pub mod routing;
pub mod rule;

use penguin_core::id::ProfileId;
use serde::{Deserialize, Serialize};

use self::app::AppConfig;
use self::dns::DnsConfig;
use self::network::NetworkConfig;
use self::profile::Profile;
use self::routing::RoutingConfig;

/// Версия схемы, которую понимает эта сборка.
///
/// Растёт только при изменении, которое старая сборка не переживёт. Новое
/// поле с умолчанием версию не двигает: файл от старой версии разберётся, а
/// новый файл старая версия прочитает, потеряв незнакомое поле, — и это
/// приемлемо ровно до тех пор, пока потеря не меняет поведения.
pub const SCHEMA_VERSION: u32 = 2;

/// Всё содержимое файла настроек.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RootConfig {
    /// Версия схемы.
    pub version: u32,
    /// Настройки приложения.
    pub app: AppConfig,
    /// Сеть: TUN, локальные прокси, защита от утечек.
    pub network: NetworkConfig,
    /// Разрешение имён.
    pub dns: DnsConfig,
    /// Режим и правила маршрутизации.
    pub routing: RoutingConfig,
    /// Профили подключения.
    pub profiles: Vec<Profile>,
    /// Какой профиль поднимать.
    pub active_profile: Option<ProfileId>,
}

impl Default for RootConfig {
    fn default() -> Self {
        Self {
            version: SCHEMA_VERSION,
            app: AppConfig::default(),
            network: NetworkConfig::default(),
            dns: DnsConfig::default(),
            routing: RoutingConfig::default(),
            profiles: Vec::new(),
            active_profile: None,
        }
    }
}

impl RootConfig {
    /// Профиль по идентификатору.
    pub fn profile(&self, id: &ProfileId) -> Option<&Profile> {
        self.profiles.iter().find(|p| &p.id == id)
    }

    /// Профиль, который надо поднимать.
    ///
    /// Если явно выбранного нет — первый в списке: клиент с единственным
    /// профилем не должен требовать выбирать его руками.
    pub fn active(&self) -> Option<&Profile> {
        match &self.active_profile {
            Some(id) => self.profile(id),
            None => self.profiles.first(),
        }
    }
}
