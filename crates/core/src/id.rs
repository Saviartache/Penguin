//! Newtype-идентификаторы: `ProfileId`, `OutboundId`, `RuleId`. Их нельзя перепутать местами.
//!
//! Все три — строки, и без обёрток компилятор молча пропустил бы вызов, где
//! на месте профиля стоит правило. Обёртки стоят ноль во время выполнения и
//! ловят такое на сборке.

use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Arc<str>);

        impl $name {
            /// Оборачивает строку.
            pub fn new(value: impl AsRef<str>) -> Self {
                Self(Arc::from(value.as_ref()))
            }

            /// Строка внутри.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::new(value)
            }
        }

        // Вручную, а не через `derive`: `Arc<str>` умеет serde только под
        // фичей `rc`, а включать её ради трёх обёрток — тянуть поддержку
        // ссылочных циклов во весь workspace.
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
                ser.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
                Ok(Self::new(String::deserialize(de)?))
            }
        }
    };
}

string_id! {
    /// Профиль подключения.
    ProfileId
}

string_id! {
    /// Исходящее направление. `direct` зарезервирован за прямым выходом.
    OutboundId
}

string_id! {
    /// Правило маршрутизации. Живёт дольше, чем его позиция в списке.
    RuleId
}

impl OutboundId {
    /// Прямой выход мимо тоннеля.
    pub fn direct() -> Self {
        Self::new(Self::DIRECT)
    }

    /// Имя прямого выхода. Занято: профиль с таким именем завести нельзя.
    pub const DIRECT: &'static str = "direct";

    /// Это прямой выход.
    pub fn is_direct(&self) -> bool {
        self.as_str() == Self::DIRECT
    }
}

impl From<ProfileId> for OutboundId {
    /// Направление именуется по профилю: они соответствуют один к одному.
    fn from(profile: ProfileId) -> Self {
        Self(profile.0)
    }
}
