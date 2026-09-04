//! `Uuid` — шестнадцать байт, которыми VMess, VLESS, TUIC и Juicity опознают
//! пользователя.
//!
//! Отдельный тип, а не `[u8; 16]`, ради двух вещей.
//!
//! **Это учётные данные.** У VLESS UUID — единственное, что отличает своего от
//! чужого; пароля рядом с ним нет. Значит, в журнал он не уходит, и `Debug`
//! здесь написан руками (`AGENTS.md` §5.2). Производный вывел бы все
//! шестнадцать байт в первой же строке отладки.
//!
//! **Разбирается он не только в одном виде.** Канонический — с дефисами,
//! но конфигурации приходят от провайдеров как есть, и в них встречается
//! запись без дефисов и в фигурных скобках.
//!
//! Чего здесь нет: вывода шестнадцати байт из произвольной строки. v2ray
//! разрешает вместо UUID любой текст и превращает его в байты через MD5 —
//! но MD5 в `core` нет и не будет, а нужен он ровно одному протоколу.
//! Живёт это преобразование в крейте VMess, рядом с остальной его
//! криптографией.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{CoreError, CoreResult};

/// Шестнадцать байт, опознающих пользователя.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uuid([u8; 16]);

impl Uuid {
    /// Оборачивает готовые байты.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Байты как они уходят в сеть.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// UUID из одних нулей.
    ///
    /// Не «пусто»: сервер такой UUID примет, если он у него настроен. Нужен
    /// тестам и как разумное начальное значение.
    pub const fn nil() -> Self {
        Self([0; 16])
    }

    /// Это UUID из одних нулей.
    pub fn is_nil(&self) -> bool {
        self.0 == [0; 16]
    }
}

impl FromStr for Uuid {
    type Err = CoreError;

    fn from_str(text: &str) -> CoreResult<Self> {
        let trimmed = text.trim();
        // Фигурные скобки приходят из конфигураций, написанных на Windows.
        let bare = trimmed
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
            .unwrap_or(trimmed);

        let mut bytes = [0u8; 16];
        let mut filled = 0;
        let mut high: Option<u8> = None;

        for symbol in bare.bytes() {
            if symbol == b'-' {
                continue;
            }
            let digit = hex_value(symbol).ok_or_else(|| bad("посторонний символ"))?;
            match high {
                None => high = Some(digit),
                Some(first) => {
                    if filled == 16 {
                        return Err(bad("длиннее шестнадцати байт"));
                    }
                    bytes[filled] = (first << 4) | digit;
                    filled += 1;
                    high = None;
                }
            }
        }

        if high.is_some() {
            return Err(bad("нечётное число шестнадцатеричных цифр"));
        }
        if filled != 16 {
            return Err(bad("короче шестнадцати байт"));
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for Uuid {
    /// Канонический вид: строчные буквы, дефисы после 4, 6, 8 и 10 байта.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Uuid {
    /// Заглушка вместо значения: это учётные данные (`AGENTS.md` §5.2).
    ///
    /// Ноль показывается отдельно, потому что «UUID не задан» — самая частая
    /// ошибка настройки, и различить её в журнале надо, не показывая
    /// настоящий.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_nil() {
            f.write_str("Uuid(нули)")
        } else {
            f.write_str("Uuid(скрыт)")
        }
    }
}

impl Serialize for Uuid {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Uuid {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let text = String::deserialize(de)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Ошибка разбора.
fn bad(reason: &'static str) -> CoreError {
    CoreError::InvalidEncoding {
        format: "UUID",
        reason: reason.to_owned(),
    }
}

/// Значение шестнадцатеричной цифры.
fn hex_value(symbol: u8) -> Option<u8> {
    match symbol {
        b'0'..=b'9' => Some(symbol - b'0'),
        b'a'..=b'f' => Some(symbol - b'a' + 10),
        b'A'..=b'F' => Some(symbol - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const BYTES: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
        0x11,
    ];

    #[test]
    fn the_canonical_form_round_trips() {
        let uuid: Uuid = TEXT.parse().unwrap();
        assert_eq!(uuid.as_bytes(), &BYTES);
        assert_eq!(uuid.to_string(), TEXT);
    }

    #[test]
    fn the_forms_providers_actually_send_are_accepted() {
        // Конфигурацию приносят как есть, и в ней встречается всё это.
        let expected: Uuid = TEXT.parse().unwrap();
        for form in [
            "b831381d63244d53ad4f8cda48b30811",
            "B831381D-6324-4D53-AD4F-8CDA48B30811",
            "{b831381d-6324-4d53-ad4f-8cda48b30811}",
            "  b831381d-6324-4d53-ad4f-8cda48b30811\n",
        ] {
            assert_eq!(form.parse::<Uuid>().unwrap(), expected, "{form}");
        }
    }

    #[test]
    fn output_is_always_canonical() {
        // Как бы ни записали на входе, наружу уходит один вид: иначе один и
        // тот же профиль сравнивался бы сам с собой как разный.
        let uuid: Uuid = "B831381D63244D53AD4F8CDA48B30811".parse().unwrap();
        assert_eq!(uuid.to_string(), TEXT);
    }

    #[test]
    fn a_short_uuid_is_rejected() {
        // Молча дополнить нулями значит подключаться под чужим именем.
        assert!("b831381d-6324".parse::<Uuid>().is_err());
        assert!("".parse::<Uuid>().is_err());
    }

    #[test]
    fn a_long_uuid_is_rejected() {
        assert!(
            "b831381d63244d53ad4f8cda48b3081100"
                .parse::<Uuid>()
                .is_err()
        );
    }

    #[test]
    fn an_odd_number_of_digits_is_rejected() {
        assert!("b831381d63244d53ad4f8cda48b3081".parse::<Uuid>().is_err());
    }

    #[test]
    fn a_stray_symbol_is_rejected() {
        // Пароль, вставленный в поле UUID, — обычная ошибка, и ответ на неё
        // должен быть «это не UUID», а не молчание.
        assert!("не-ууид-а-пароль".parse::<Uuid>().is_err());
        assert!(
            "b831381d 6324 4d53 ad4f 8cda48b30811"
                .parse::<Uuid>()
                .is_err()
        );
    }

    #[test]
    fn debug_keeps_the_value_out_of_the_log() {
        let uuid: Uuid = TEXT.parse().unwrap();
        let shown = format!("{uuid:?}");
        assert!(!shown.contains("b831"), "{shown}");
        assert_eq!(format!("{:?}", Uuid::nil()), "Uuid(нули)");
    }

    #[test]
    fn serde_speaks_the_canonical_form() {
        let uuid: Uuid = TEXT.parse().unwrap();
        let json = serde_json::to_string(&uuid).unwrap();
        assert_eq!(json, format!("\"{TEXT}\""));
        assert_eq!(serde_json::from_str::<Uuid>(&json).unwrap(), uuid);
        assert!(serde_json::from_str::<Uuid>("\"нет\"").is_err());
    }
}
