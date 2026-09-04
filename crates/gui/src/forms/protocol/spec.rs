//! Описание протокола для формы: поля, их место в настройках, проверки.
//!
//! Всё здесь — константы: описание не меняется во время работы, и собирать его
//! на каждую отрисовку незачем. Отсюда `const fn`-сборщики: они позволяют
//! писать описание протокола так, как оно читается, — по полю на строку, без
//! девяти `None` в каждом.

use crate::forms::link::Link;
use crate::i18n::Strings;

/// Подпись, взятая из таблицы текущего языка.
///
/// Указатель на функцию, а не готовая строка: описание протокола — константа,
/// а язык выбирается при запуске, и подставить его в константу нельзя.
pub type Label = fn(&Strings) -> &'static str;

/// Проверка набранного значения. `Err` — текст, который показывают как есть.
pub type Check = fn(&str) -> Result<(), String>;

/// Как ссылка-приглашение ложится в поля: пары «имя поля — значение».
pub type FromLink = fn(&Link) -> Result<Vec<(&'static str, String)>, String>;

/// Вид поля — им же задаётся, каким виджетом его показать.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// Обычная строка.
    Text,
    /// Строка, которую не показывают: пароль или ключ.
    Secret,
    /// Переключатель.
    Flag,
    /// Выбор из известного набора.
    ///
    /// Заводится не ради удобства: перенос у Trojan, метод шифрования
    /// Shadowsocks и версия Snell — это поля, где опечатка означает не
    /// «сервер отказал», а «сервер молчит», и искать её человек будет в сети.
    /// Набор, который нельзя набрать руками, снимает этот вопрос целиком.
    Choice,
}

/// Одно поле формы.
pub struct FieldSpec {
    /// Имя поля внутри протокола: по нему поле ищут в черновике и в тестах.
    pub key: &'static str,
    /// Куда набранное ложится в параметрах: `["tls", "sni"]`.
    ///
    /// Пустое значение не пишется вовсе, а группа, у которой не осталось ни
    /// одного поля, не заводится. Настройки лежат в TOML, а в нём пустого
    /// значения не существует: `null` там ломает запись **всех** настроек
    /// целиком, причём молча для того, кто просто не заполнил поле.
    pub path: &'static [&'static str],
    /// Чем показать.
    pub kind: FieldKind,
    /// Подпись.
    pub label: Label,
    /// Подсказка внутри поля.
    pub example: Option<Label>,
    /// Что сказать, если поле обязательное и не заполнено.
    ///
    /// `None` — поле необязательное. Текст свой у каждого поля: «заполните
    /// поле» не отвечает на вопрос, какое именно.
    pub required: Option<Label>,
    /// Проверка значения, если оно заполнено.
    pub check: Option<Check>,
    /// Что записать рядом, когда поле заполнено.
    ///
    /// Ради `obfs.type = "salamander"`: тип обфускации не спрашивают, но без
    /// него пароль обфускации не значит ничего.
    pub with: &'static [(&'static [&'static str], &'static str)],
    /// Каким переключатель стоит в новом профиле.
    ///
    /// Он же — значение, которым поле читается, когда в настройках его нет:
    /// у переключателя, включённого по умолчанию, отсутствие в файле означает
    /// «включено», и прочитать его как «выключено» значило бы показать
    /// снятый флажок там, где на самом деле всё работает.
    ///
    /// Отсюда же правило записи: переключатель пишется, только когда он
    /// **отличается** от умолчания. Так файл настроек остаётся коротким, а
    /// прочитанное совпадает с записанным.
    pub default_on: bool,
    /// Что можно выбрать. Значимо только у [`FieldKind::Choice`].
    ///
    /// Первое значение — умолчание нового профиля. Пустым у поля выбора не
    /// бывает: пустой список в форме обещает выбор, которого в нём нет.
    pub options: &'static [&'static str],
    /// Откуда ещё прочитать значение при открытии профиля.
    ///
    /// Конфигурацию приносят от провайдера как есть, и одно и то же поле в ней
    /// зовётся по-разному: у Hysteria 2 пароль — то `password`, то `auth`.
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

    /// Значение, с которым поле заводится в новом профиле.
    ///
    /// У выбора это первое из набора; у остальных — пусто.
    pub fn default_text(&self) -> &'static str {
        match self.kind {
            FieldKind::Choice => self.options.first().copied().unwrap_or_default(),
            _ => "",
        }
    }
}

/// Описание протокола целиком.
pub struct ProtocolSpec {
    /// Имя протокола в настройках: `socks5`. Стоит в файлах пользователей —
    /// менять нельзя.
    pub id: &'static str,
    /// Имя для человека: `SOCKS5`.
    ///
    /// Не переводится: это имя протокола, а не подпись. «Гистерия 2» никто не
    /// ищет.
    pub label: &'static str,
    /// Поля формы в том порядке, в каком их показывают.
    pub fields: &'static [FieldSpec],
    /// Схемы ссылок-приглашений: `["hy2://", "hysteria2://"]`.
    ///
    /// Пусто — ссылок у протокола не бывает, и поле вставки ему не
    /// показывается.
    pub schemes: &'static [&'static str],
    /// Как ссылка ложится в поля.
    ///
    /// Возвращает пары «имя поля — значение». `Err` — текст, который можно
    /// показать как есть. Обязателен, если [`Self::schemes`] непуст; это
    /// проверяется тестом.
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
        // Поля целиком в выводе не нужны: это описание, а не состояние, и в
        // журнале от него полезно только имя.
        f.debug_struct("ProtocolSpec")
            .field("id", &self.id)
            .field("fields", &self.fields.len())
            .finish()
    }
}

impl PartialEq for ProtocolSpec {
    /// Описания сравниваются по имени протокола: их по одному на протокол, и
    /// два разных с одним именем — это ошибка каталога, которую ловит его
    /// собственный тест.
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ProtocolSpec {}
