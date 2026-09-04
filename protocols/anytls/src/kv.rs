//! Формат `ключ=значение`: строки, разделённые переводом строки.
//!
//! Им записаны и настройки сессии (`cmdSettings`, `cmdServerSettings`), и
//! схема дополнения. Формат нарочно простой, и разбор у него **прощающий**:
//! строка без `=` пропускается, а не роняет разбор. Так устроен эталон, и
//! иначе одна лишняя строка в схеме от нового сервера рвала бы соединение.
//!
//! Порядок ключей при сборке — тот, в котором их клали. У эталона порядок
//! случайный (карта Go), серверу он безразличен, а нам нужен предсказуемый:
//! иначе кадр настроек нельзя проверить тестом.

/// Набор пар `ключ=значение`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Map(Vec<(String, String)>);

impl Map {
    /// Пустой набор.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Кладёт пару. Ключ, который уже есть, заменяется.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        match self.0.iter_mut().find(|(known, _)| *known == key) {
            Some(slot) => slot.1 = value,
            None => self.0.push((key, value)),
        }
    }

    /// Значение по ключу.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(known, _)| known == key)
            .map(|(_, value)| value.as_str())
    }

    /// Ключи в том порядке, в каком их клали.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(key, _)| key.as_str())
    }

    /// Записывает набор байтами.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut lines = Vec::with_capacity(self.0.len());
        for (key, value) in &self.0 {
            lines.push(format!("{key}={value}"));
        }
        lines.join("\n").into_bytes()
    }

    /// Разбирает набор из байт.
    ///
    /// Строки без `=` пропускаются. Первый `=` — разделитель: всё правее него
    /// принадлежит значению, включая другие `=`.
    pub fn parse(bytes: &[u8]) -> Self {
        let text = String::from_utf8_lossy(bytes);
        let mut map = Self::new();
        for line in text.split('\n') {
            if let Some((key, value)) = line.split_once('=') {
                map.set(key, value);
            }
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_set_survives_the_round_trip() {
        let mut map = Map::new();
        map.set("v", "2");
        map.set("client", "penguin/0.1.0");
        assert_eq!(map.to_bytes(), b"v=2\nclient=penguin/0.1.0");
        assert_eq!(Map::parse(&map.to_bytes()), map);
    }

    #[test]
    fn the_first_sign_is_the_separator() {
        // Схема дополнения содержит `=` внутри значения, и терять хвост
        // означает читать не ту схему.
        let map = Map::parse(b"2=400-500,c,500-1000");
        assert_eq!(map.get("2"), Some("400-500,c,500-1000"));

        let map = Map::parse(b"a=b=c");
        assert_eq!(map.get("a"), Some("b=c"));
    }

    #[test]
    fn a_line_without_a_sign_is_skipped() {
        // Так устроен эталон: лишняя строка от нового сервера не должна рвать
        // соединение.
        let map = Map::parse("v=2\n\nмусор\nclient=x".as_bytes());
        assert_eq!(map.get("v"), Some("2"));
        assert_eq!(map.get("client"), Some("x"));
        assert_eq!(map.keys().count(), 2);
    }

    #[test]
    fn the_last_value_of_a_key_wins() {
        let map = Map::parse(b"v=1\nv=2");
        assert_eq!(map.get("v"), Some("2"));
    }

    #[test]
    fn the_order_of_keys_is_the_order_they_were_put_in() {
        // Кадр настроек проверяется тестом побайтно, а значит порядок обязан
        // быть предсказуемым.
        let mut map = Map::new();
        map.set("b", "1");
        map.set("a", "2");
        map.set("b", "3");
        assert_eq!(map.to_bytes(), b"b=3\na=2");
    }

    #[test]
    fn an_empty_value_is_still_a_value() {
        // Пустое имя клиента — законная настройка: она означает «не
        // представляться».
        let map = Map::parse(b"client=");
        assert_eq!(map.get("client"), Some(""));
    }

    #[test]
    fn bytes_that_are_not_text_do_not_break_the_parse() {
        let map = Map::parse(&[b'v', b'=', 0xff, b'\n', b'a', b'=', b'1']);
        assert_eq!(map.get("a"), Some("1"));
    }
}
