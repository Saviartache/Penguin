//! Версии протокола: пять штук, и они не совместимы между собой.
//!
//! Умолчания здесь нет и быть не должно. Неверная версия не даёт отказа: она
//! даёт молчащее соединение, потому что сервер расшифровывает первый кусок
//! другим шифром и видит мусор. Человек в этом случае ищет неисправность в
//! сети, а она в одном числе.
//!
//! | Версия | Шифр | UDP | Кадр |
//! |---|---|---|---|
//! | 1 | ChaCha20-Poly1305 | нет | общий, как у Shadowsocks |
//! | 2 | AES-128-GCM | нет | тот же, но соединение переиспользуемое |
//! | 3 | AES-128-GCM | да | тот же |
//! | 4 | AES-128-GCM | да | свой, с дополнением |
//! | 5 | AES-128-GCM | да | тот же, что у 4 |
//!
//! Шифр взят из кода двух независимых реализаций. Разборы протокола пишут,
//! что он везде ChaCha20-Poly1305, — это верно только для первой версии, и
//! код тех же авторов говорит иначе.

use penguin_transport::aead::Algorithm;
use serde::de::{Error as DeError, Unexpected};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Версия протокола.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    /// Первая: ChaCha20-Poly1305, без UDP.
    V1,
    /// Соединение переиспользуемое: одно TCP несёт запросы подряд.
    V2,
    /// Появился UDP.
    V3,
    /// Свой кадр с дополнением вместо общего.
    V4,
    /// То же, что четвёртая. Различие — вне провода.
    V5,
}

impl Version {
    /// Номер версии, как он стоит в настройках.
    pub fn number(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
            Self::V5 => 5,
        }
    }

    /// Версия по номеру. `None` — такой не бывает.
    pub fn parse(number: u8) -> Option<Self> {
        match number {
            1 => Some(Self::V1),
            2 => Some(Self::V2),
            3 => Some(Self::V3),
            4 => Some(Self::V4),
            5 => Some(Self::V5),
            _ => None,
        }
    }

    /// Каким шифром закрываются куски.
    ///
    /// У первой версии он свой, у остальных общий. Ошибка здесь не видна
    /// ничем, кроме молчания сервера.
    pub fn algorithm(self) -> Algorithm {
        match self {
            Self::V1 => Algorithm::ChaCha20Poly1305,
            _ => Algorithm::Aes128Gcm,
        }
    }

    /// Умеет ли эта версия возить датаграммы.
    pub fn udp(self) -> bool {
        self >= Self::V3
    }

    /// Своё ли у этой версии обрамление.
    ///
    /// С четвёртой общий кадр Shadowsocks заменён своим — с дополнением и
    /// собственным заголовком у каждой посылки.
    pub fn framed(self) -> bool {
        self >= Self::V4
    }

    /// Открывается ли соединение командой переиспользования.
    ///
    /// Вторая версия шлёт её всегда: этим она и отличается от первой. Прочие
    /// шлют обычную.
    pub fn reusable(self) -> bool {
        self == Self::V2
    }
}

impl From<Version> for u8 {
    fn from(version: Version) -> Self {
        version.number()
    }
}

impl TryFrom<u8> for Version {
    type Error = String;

    fn try_from(number: u8) -> Result<Self, Self::Error> {
        Self::parse(number)
            .ok_or_else(|| format!("версия Snell {number}: бывают только с первой по пятую"))
    }
}

impl Serialize for Version {
    /// В файл настроек версия пишется числом: так её пишут все.
    fn serialize<S: Serializer>(&self, out: S) -> Result<S::Ok, S::Error> {
        out.serialize_u8(self.number())
    }
}

impl<'de> Deserialize<'de> for Version {
    /// Читается и числом, и строкой.
    ///
    /// Строкой её кладёт окно: поле выбора отдаёт текст, а заводить ради
    /// одного протокола числовое поле в форме дороже, чем принять здесь обе
    /// записи. Числом её пишут в файлах руками и все прочие клиенты.
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        let raw = serde_json::Value::deserialize(input)?;
        let number = match &raw {
            serde_json::Value::Number(number) => number.as_u64(),
            serde_json::Value::String(text) => text.trim().parse::<u64>().ok(),
            _ => None,
        };

        let number = number.ok_or_else(|| {
            DeError::invalid_type(Unexpected::Other(&raw.to_string()), &"версия Snell числом")
        })?;
        u8::try_from(number)
            .ok()
            .and_then(Self::parse)
            .ok_or_else(|| {
                DeError::custom(format!(
                    "версия Snell {number}: бывают только с первой по пятую"
                ))
            })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.number())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Version; 5] = [
        Version::V1,
        Version::V2,
        Version::V3,
        Version::V4,
        Version::V5,
    ];

    #[test]
    fn every_version_survives_the_round_trip() {
        for version in ALL {
            assert_eq!(Version::parse(version.number()), Some(version));
        }
    }

    #[test]
    fn there_is_no_version_zero_and_no_version_six() {
        // Умолчания нет нарочно: неверная версия даёт молчание, а не отказ.
        assert!(Version::parse(0).is_none());
        assert!(Version::parse(6).is_none());
        assert!(serde_json::from_str::<Version>("6").is_err());
    }

    #[test]
    fn only_the_first_version_uses_chacha() {
        // Разборы протокола пишут, что ChaCha20 везде. Код двух реализаций
        // говорит иначе, и здесь стоит то, что говорит код.
        assert_eq!(Version::V1.algorithm(), Algorithm::ChaCha20Poly1305);
        for version in [Version::V2, Version::V3, Version::V4, Version::V5] {
            assert_eq!(version.algorithm(), Algorithm::Aes128Gcm, "{version}");
        }
    }

    #[test]
    fn udp_starts_at_the_third_version() {
        assert!(!Version::V1.udp());
        assert!(!Version::V2.udp());
        for version in [Version::V3, Version::V4, Version::V5] {
            assert!(version.udp(), "{version}");
        }
    }

    #[test]
    fn the_frame_changes_at_the_fourth() {
        for version in [Version::V1, Version::V2, Version::V3] {
            assert!(!version.framed(), "{version}");
        }
        assert!(Version::V4.framed());
        assert!(Version::V5.framed());
    }

    #[test]
    fn only_the_second_version_always_asks_for_reuse() {
        for version in ALL {
            assert_eq!(version.reusable(), version == Version::V2, "{version}");
        }
    }

    #[test]
    fn the_number_is_what_goes_into_the_settings() {
        let version: Version = serde_json::from_str("3").expect("разбирается");
        assert_eq!(version, Version::V3);
        assert_eq!(serde_json::to_string(&version).expect("пишется"), "3");
    }

    #[test]
    fn a_version_written_as_text_is_read_too() {
        // Строкой её кладёт окно: поле выбора отдаёт текст.
        assert_eq!(
            serde_json::from_str::<Version>("\"4\"").expect("разбирается"),
            Version::V4
        );
        assert!(serde_json::from_str::<Version>("\"четыре\"").is_err());
        assert!(serde_json::from_str::<Version>("true").is_err());
    }
}
