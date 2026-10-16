//! Схема дополнения: сколько байт должна занимать каждая запись TLS.
//!
//! Клиент начинает со схемы [`DEFAULT`], шлёт её MD5 в настройках, и сервер с
//! другой схемой присылает свою; поля в форме нет.
//!
//! ```text
//!  stop=8
//!  0=30-30
//!  2=400-500,c,500-1000
//! ```
//!
//! `stop` — номер пакета, с которого дополнять перестают. Ключ — номер записи
//! TLS, значение — «мин-макс» (размер) или `c` (данные кончились — не дополнять).
//! Сервер размеры не проверяет, поэтому негодную схему можно отвергнуть.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use md5::{Digest, Md5};
use penguin_proto::random;

use crate::kv::Map;

/// Схема, с которой клиент начинает.
///
/// Байты — те же, что у эталона, вплоть до отсутствия перевода строки в
/// конце: по её отпечатку сервер решает, присылать ли свою.
pub const DEFAULT: &[u8] = b"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

/// Наибольший размер записи, который схема вправе назвать.
///
/// Длина кадра пишется двумя байтами; размер больше этого пришлось бы
/// обрезать, и запись вышла бы не той длины, какую назвали. Такую схему проще
/// не принять.
pub const MAX_SIZE: usize = u16::MAX as usize;

/// Что схема велит сделать с очередной записью.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Размер записи — число из промежутка. Верхняя граница не входит.
    Range {
        /// Наименьший размер.
        min: usize,
        /// Наибольший, не включая его самого.
        max: usize,
    },
    /// Проверка: данные кончились — дальше не дополнять.
    Check,
}

/// Что схема назначила конкретной записи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Записать столько байт.
    Size(usize),
    /// Данные кончились — дальше не дополнять.
    Check,
}

/// Разобранная схема.
#[derive(Debug, Clone)]
pub struct Scheme {
    /// Байты, как их прислали: их отпечаток уходит серверу.
    raw: Vec<u8>,
    /// Отпечаток MD5 в шестнадцатеричной записи, строчными буквами.
    md5: String,
    /// Номер пакета, с которого дополнять перестают.
    stop: u32,
    /// Правила по номерам пакетов.
    rules: HashMap<u32, Vec<Rule>>,
}

impl Scheme {
    /// Разбирает схему; `None` — нет `stop`, он не число или размер не влезает в кадр.
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let map = Map::parse(raw);
        let stop: i64 = map.get("stop")?.parse().ok()?;
        let stop = u32::try_from(stop).ok()?;

        let mut rules = HashMap::new();
        for key in map.keys() {
            let Ok(pkt) = key.parse::<u32>() else {
                continue;
            };
            let value = map.get(key).unwrap_or_default();
            rules.insert(pkt, parse_rules(value)?);
        }

        Some(Self {
            raw: raw.to_vec(),
            md5: Md5::digest(raw)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            stop,
            rules,
        })
    }

    /// Байты схемы, как их прислали.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Отпечаток: он уходит серверу в настройках.
    pub fn md5(&self) -> &str {
        &self.md5
    }

    /// Номер пакета, с которого дополнять перестают.
    pub fn stop(&self) -> u32 {
        self.stop
    }

    /// Что делать с записью номер `pkt`; размеры разыгрываются на каждый вызов.
    pub fn steps(&self, pkt: u32) -> Vec<Step> {
        let Some(rules) = self.rules.get(&pkt) else {
            return Vec::new();
        };
        rules
            .iter()
            .map(|rule| match *rule {
                Rule::Check => Step::Check,
                Rule::Range { min, max } if min >= max => Step::Size(min),
                Rule::Range { min, max } => {
                    Step::Size(random::range(min as u64..max as u64) as usize)
                }
            })
            .collect()
    }
}

impl Default for Scheme {
    fn default() -> Self {
        Self::parse(DEFAULT).unwrap_or(Self {
            raw: Vec::new(),
            md5: String::new(),
            stop: 0,
            rules: HashMap::new(),
        })
    }
}

/// Правила одной записи (`400-500,c,500-1000`); неразбираемые части пропускаются
/// как у эталона, `None` — размер не влезает в кадр.
fn parse_rules(value: &str) -> Option<Vec<Rule>> {
    let mut rules = Vec::new();
    for part in value.split(',') {
        if part == "c" {
            rules.push(Rule::Check);
            continue;
        }
        let Some((low, high)) = part.split_once('-') else {
            continue;
        };
        let (Ok(low), Ok(high)) = (low.parse::<i64>(), high.parse::<i64>()) else {
            continue;
        };
        let (min, max) = (low.min(high), low.max(high));
        if min <= 0 || max <= 0 {
            continue;
        }
        if max > MAX_SIZE as i64 {
            return None;
        }
        rules.push(Rule::Range {
            min: min as usize,
            max: max as usize,
        });
    }
    Some(rules)
}

/// Схема направления; общая для сессий, потому что принадлежит серверу.
#[derive(Debug)]
pub struct Padding(RwLock<Arc<Scheme>>);

impl Padding {
    /// Заводит состояние со схемой по умолчанию.
    pub fn new() -> Self {
        Self(RwLock::new(Arc::new(Scheme::default())))
    }

    /// Схема, действующая сейчас.
    pub fn get(&self) -> Arc<Scheme> {
        match self.0.read() {
            Ok(scheme) => Arc::clone(&scheme),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Принимает схему сервера; `false` — не разобралась, прежняя остаётся.
    pub fn update(&self, raw: &[u8]) -> bool {
        let Some(scheme) = Scheme::parse(raw) else {
            return false;
        };
        match self.0.write() {
            Ok(mut slot) => *slot = Arc::new(scheme),
            Err(poisoned) => *poisoned.into_inner() = Arc::new(scheme),
        }
        true
    }
}

impl Default for Padding {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_scheme_is_the_one_the_reference_ships() {
        let scheme = Scheme::parse(DEFAULT).expect("разбирается");
        assert_eq!(scheme.stop(), 8);

        assert_eq!(scheme.md5(), "75cff2ad89aadf5e257059ee571ebe11");
        assert_eq!(scheme.raw().len(), 137);
        assert!(!scheme.raw().ends_with(b"\n"), "лишний перевод строки");
    }

    #[test]
    fn the_first_packet_is_exactly_thirty_bytes() {
        let scheme = Scheme::parse(DEFAULT).expect("разбирается");
        assert_eq!(scheme.steps(0), vec![Step::Size(30)]);
    }

    #[test]
    fn a_range_stays_inside_itself_and_never_touches_the_top() {
        let scheme = Scheme::parse(b"stop=2\n1=100-400").expect("разбирается");
        for _ in 0..200 {
            let Some(Step::Size(size)) = scheme.steps(1).first().copied() else {
                panic!("правило потерялось");
            };
            assert!((100..400).contains(&size), "{size}");
        }
    }

    #[test]
    fn the_check_mark_keeps_its_place_among_the_sizes() {
        let scheme = Scheme::parse(DEFAULT).expect("разбирается");
        let steps = scheme.steps(2);
        assert_eq!(steps.len(), 9);
        assert_eq!(steps[1], Step::Check);
        assert_eq!(steps[3], Step::Check);
        assert!(matches!(steps[0], Step::Size(size) if (400..500).contains(&size)));
    }

    #[test]
    fn a_packet_the_scheme_says_nothing_about_is_sent_as_is() {
        let scheme = Scheme::parse(DEFAULT).expect("разбирается");
        assert!(scheme.steps(50).is_empty());
    }

    #[test]
    fn a_scheme_without_a_stop_is_refused() {
        assert!(Scheme::parse(b"0=30-30").is_none());
        assert!(Scheme::parse(b"stop=\n0=30-30").is_none());
        assert!(Scheme::parse(b"stop=many").is_none());
        assert!(Scheme::parse(b"").is_none());
    }

    #[test]
    fn a_negative_stop_is_refused() {
        assert!(Scheme::parse(b"stop=-1\n0=30-30").is_none());
    }

    #[test]
    fn a_size_that_does_not_fit_the_frame_is_refused() {
        assert!(Scheme::parse(b"stop=2\n1=1-65535").is_some());
        assert!(Scheme::parse(b"stop=2\n1=1-65536").is_none());
    }

    #[test]
    fn a_part_that_does_not_parse_is_skipped() {
        let scheme = Scheme::parse("stop=2\n1=30-30,,мусор,40-40".as_bytes()).expect("разбирается");
        assert_eq!(scheme.steps(1), vec![Step::Size(30), Step::Size(40)]);

        let scheme = Scheme::parse(b"stop=2\n1=0-0,40-40").expect("разбирается");
        assert_eq!(scheme.steps(1), vec![Step::Size(40)]);
    }

    #[test]
    fn the_bounds_of_a_range_may_come_in_either_order() {
        let scheme = Scheme::parse(b"stop=2\n1=400-100").expect("разбирается");
        let Some(Step::Size(size)) = scheme.steps(1).first().copied() else {
            panic!("правило потерялось");
        };
        assert!((100..400).contains(&size), "{size}");
    }

    #[test]
    fn a_scheme_the_server_sent_replaces_the_one_before_it() {
        let padding = Padding::new();
        let before = padding.get().md5().to_owned();

        assert!(padding.update(b"stop=2\n1=100-100"));
        assert_ne!(padding.get().md5(), before);
        assert_eq!(padding.get().stop(), 2);
    }

    #[test]
    fn a_scheme_that_does_not_parse_leaves_the_old_one_alone() {
        let padding = Padding::new();
        let before = padding.get().md5().to_owned();
        assert!(!padding.update("мусор".as_bytes()));
        assert_eq!(padding.get().md5(), before);
    }
}
