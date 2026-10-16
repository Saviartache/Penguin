//! Общие помощники тестов разбора ссылок.

use crate::forms::link::{self, Link};

/// Пары «поле — значение», которые даёт разбор ссылки.
pub type Values = Vec<(&'static str, String)>;

/// Разбирает ссылку протокола, паникуя на ошибке.
pub fn parse(from_link: fn(&Link) -> Result<Values, String>, raw: &str) -> Values {
    let link = link::split(raw).expect("ссылка разбирается");
    from_link(&link).expect("поля заполняются")
}

/// Значение поля по имени.
pub fn value<'a>(values: &'a [(&'static str, String)], key: &str) -> Option<&'a str> {
    values
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value.as_str())
}
