//! Описание протокола для формы: поля, их место в настройках, проверки.
//!
//! Всё константы; `const fn`-сборщики дают писать по полю на строку.

use crate::forms::link::Link;
use crate::i18n::Strings;

/// Подпись из таблицы текущего языка (язык выбирается при запуске, в константу не подставить).
pub type Label = fn(&Strings) -> &'static str;

/// Проверка набранного значения; `Err` — текст для показа как есть.
pub type Check = fn(&str) -> Result<(), String>;

/// Как ссылка ложится в поля: пары «имя поля — значение».
pub type FromLink = fn(&Link) -> Result<Vec<(&'static str, String)>, String>;

/// Вид поля — им же задаётся виджет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// Обычная строка.
    Text,
    /// Строка, которую не показывают: пароль или ключ.
    Secret,
    /// Переключатель.
    Flag,
    /// Выбор из известного набора: опечатка в метода шифрования даёт молчащий сервер.
    Choice,
}

/// Одно поле формы.
pub struct FieldSpec {
    /// Имя поля внутри протокола.
    pub key: &'static str,
    /// Куда набранное ложится в параметрах: `["tls", "sni"]`. Пустое значение
    /// не пишется, пустая группа не заводится: `null` ломает запись TOML.
    pub path: &'static [&'static str],
    /// Чем показать.
    pub kind: FieldKind,
    /// Подпись.
    pub label: Label,
    /// Подсказка внутри поля.
    pub example: Option<Label>,
    /// Что сказать, если поле обязательное и пусто; `None` — необязательное.
    pub required: Option<Label>,
    /// Проверка значения, если оно заполнено.
    pub check: Option<Check>,
    /// Что записать рядом, когда поле заполнено (`obfs.type = "salamander"`).
    pub with: &'static [(&'static [&'static str], &'static str)],
    /// Состояние переключателя в новом профиле и при отсутствии в файле;
    /// пишется только отличие от него.
    pub default_on: bool,
    /// Набор [`FieldKind::Choice`]; первое значение — умолчание, пустым не бывает.
    pub options: &'static [&'static str],
    /// Откуда ещё читать значение (у Hysteria 2 пароль — `password` или `auth`).
    pub also: &'static [&'static [&'static str]],
}

impl FieldSpec {
    /// Строка.
    pub const fn text(key: &'static str, path: &'static [&'static str], label: Label) -> Self {
        Self {
            key,
            path,
            kind: FieldKind::Text,
            label,
            example: None,
            required: None,
            check: None,
            default_on: false,
            with: &[],
            options: &[],
            also: &[],
        }
    }

    /// Строка, которую не показывают.
    pub const fn secret(key: &'static str, path: &'static [&'static str], label: Label) -> Self {
        Self {
            kind: FieldKind::Secret,
            ..Self::text(key, path, label)
        }
    }

    /// Переключатель.
    pub const fn flag(key: &'static str, path: &'static [&'static str], label: Label) -> Self {
        Self {
            kind: FieldKind::Flag,
            ..Self::text(key, path, label)
        }
    }

    /// Выбор из набора. Первое значение — умолчание нового профиля.
    pub const fn choice(
        key: &'static str,
        path: &'static [&'static str],
        label: Label,
        options: &'static [&'static str],
    ) -> Self {
        Self {
            kind: FieldKind::Choice,
            options,
            ..Self::text(key, path, label)
        }
    }

    /// Добавляет подсказку внутри поля.
    pub const fn example(mut self, example: Label) -> Self {
        self.example = Some(example);
        self
    }

    /// Делает поле обязательным.
    pub const fn required(mut self, missing: Label) -> Self {
        self.required = Some(missing);
        self
    }

    /// Добавляет проверку значения.
    pub const fn check(mut self, check: Check) -> Self {
        self.check = Some(check);
        self
    }

    /// Делает переключатель включённым по умолчанию.
    pub const fn on(mut self) -> Self {
        self.default_on = true;
        self
    }

    /// Добавляет постоянные значения, которые пишутся вместе с полем.
    pub const fn with(mut self, with: &'static [(&'static [&'static str], &'static str)]) -> Self {
        self.with = with;
        self
    }

    /// Добавляет запасные места, откуда читать значение.
    pub const fn also(mut self, also: &'static [&'static [&'static str]]) -> Self {
        self.also = also;
        self
    }

    /// Это переключатель.
    pub fn is_flag(&self) -> bool {
        matches!(self.kind, FieldKind::Flag)
    }

    /// Значение прячется при вводе.
    pub fn is_secret(&self) -> bool {
        matches!(self.kind, FieldKind::Secret)
    }

    /// Это выбор из набора.
    pub fn is_choice(&self) -> bool {
        matches!(self.kind, FieldKind::Choice)
    }

    /// Значение в новом профиле: у выбора первое из набора, у остальных пусто.
    pub fn default_text(&self) -> &'static str {
        match self.kind {
            FieldKind::Choice => self.options.first().copied().unwrap_or_default(),
            _ => "",
        }
    }
}

/// Описание протокола целиком.
pub struct ProtocolSpec {
    /// Имя протокола в настройках: `socks5`. Стоит в файлах пользователей, менять нельзя.
    pub id: &'static str,
    /// Имя для человека, не переводится: `SOCKS5`.
    pub label: &'static str,
    /// Поля формы в порядке показа.
    pub fields: &'static [FieldSpec],
    /// Схемы ссылок: `["hy2://", "hysteria2://"]`; пусто — ссылок нет.
    pub schemes: &'static [&'static str],
    /// Как ссылка ложится в поля; обязателен при непустых `schemes` (проверяет тест).
    pub from_link: Option<FromLink>,
}

impl ProtocolSpec {
    /// Место поля в списке — им сообщения адресуют правку.
    pub fn index_of(&self, key: &str) -> Option<usize> {
        self.fields.iter().position(|field| field.key == key)
    }

    /// Умеет ли протокол разбирать ссылки-приглашения.
    pub fn takes_links(&self) -> bool {
        !self.schemes.is_empty() && self.from_link.is_some()
    }
}

impl std::fmt::Debug for ProtocolSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolSpec")
            .field("id", &self.id)
            .field("fields", &self.fields.len())
            .finish()
    }
}

impl PartialEq for ProtocolSpec {
    /// По имени: описание одно на протокол, дубль ловит тест каталога.
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ProtocolSpec {}
