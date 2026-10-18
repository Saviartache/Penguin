//! Профиль подключения: имя, метки, ссылка на outbound.

use penguin_core::id::ProfileId;
use serde::{Deserialize, Serialize};

use super::outbound::RawOutbound;

/// Один сервер в списке пользователя.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Устойчивый идентификатор. Имя пользователь меняет, ссылки — нет.
    pub id: ProfileId,
    /// Имя для интерфейса.
    pub name: String,
    /// Метки для группировки и правил.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Как подключаться.
    pub outbound: RawOutbound,
    /// Подписка-источник; профиль из неё перезаписывается при обновлении.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription: Option<String>,
    /// Страна сервера (ISO 3166-1, `JP`), если её назвал источник профиля.
    ///
    /// Нужна, когда адрес — общий вход, а не сам сервер (подписка Amnezia):
    /// GeoIP по такому адресу назовёт страну входа. Без неё страну ищет GeoIP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl Profile {
    /// Собирает профиль.
    pub fn new(id: impl Into<ProfileId>, name: impl Into<String>, outbound: RawOutbound) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            tags: Vec::new(),
            outbound,
            subscription: None,
            country: None,
        }
    }

    /// Профиль пришёл из подписки и правится не пользователем.
    pub fn is_managed(&self) -> bool {
        self.subscription.is_some()
    }
}
