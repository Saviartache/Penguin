//! Настройки рассинхронизации и то, во что они превращаются перед отправкой.
//!
//! Чистая логика: ни сокета, ни ожидания. Точку разреза можно посчитать и
//! проверить, ничего не отправляя, — этим и пользуются тесты.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{TransportError, TransportResult};

/// TTL ложной посылки, когда его не задали.
///
/// Три перехода: дальше типового места, где стоит DPI провайдера, и заведомо
/// ближе, чем сервер за границей. Число это не универсально — у `zapret2` его
/// подбирают `blockcheck`ом под конкретную сеть, — но молчаливого нуля здесь
/// быть не должно: TTL, равный нулю, означает пакет, который не уходит с
/// машины вовсе.
pub const DEFAULT_FAKE_TTL: u8 = 3;

/// Сколько кусков разреза допускается. Больше — это уже не обход DPI, а
/// сотня системных вызовов на каждое соединение.
const MAX_SPLITS: usize = 8;

/// Чем ломается сборка потока у DPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Strategy {
    /// Ничего не делать: первая посылка уходит одним куском.
    #[default]
    None,
    /// Разрезать посылку на куски и отправить их по порядку.
    ///
    /// `multisplit` у `zapret2`. Расчёт на DPI, который смотрит только на
    /// первый сегмент потока и не собирает его целиком.
    Multisplit,
    /// Разрезать и отправить не по порядку.
    ///
    /// `multidisorder` у `zapret2`. Первый кусок уходит с малым TTL и до
    /// сервера не доходит; ядро повторит его позже, и настоящий порядок
    /// восстановится. DPI к этому времени уже принял решение по тому, что
    /// пришло первым, — по середине `ClientHello`.
    Disorder,
    /// Отправить перед настоящей посылкой ложную с малым TTL.
    ///
    /// `fake` у `zapret2`. DPI разбирает ложную и запоминает её; настоящая
    /// приходит следом и выглядит для него продолжением уже разобранного
    /// потока.
    Fake,
    /// Ложная посылка и разрез сразу.
    ///
    /// `fakedsplit` у `zapret2` — то, что в большинстве сетей работает там,
    /// где по отдельности не работает ни то, ни другое.
    FakedSplit,
}

impl Strategy {
    /// Разбирает имя стратегии из настроек.
    ///
    /// Пустая строка — это «ничего не делать»: так её пишут в конфигурациях,
    /// где раздел есть, а обход не нужен.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim() {
            "" | "none" => Some(Self::None),
            "multisplit" => Some(Self::Multisplit),
            "disorder" => Some(Self::Disorder),
            "fake" => Some(Self::Fake),
            "fakedsplit" => Some(Self::FakedSplit),
            _ => None,
        }
    }

    /// Имя стратегии в настройках.
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Multisplit => "multisplit",
            Self::Disorder => "disorder",
            Self::Fake => "fake",
            Self::FakedSplit => "fakedsplit",
        }
    }

    /// Режет ли стратегия посылку на куски.
    pub fn splits(self) -> bool {
        matches!(self, Self::Multisplit | Self::Disorder | Self::FakedSplit)
    }

    /// Отправляет ли стратегия ложную посылку.
    pub fn fakes(self) -> bool {
        matches!(self, Self::Fake | Self::FakedSplit)
    }
}

/// Ориентир внутри посылки, от которого считается точка разреза.
///
/// Абсолютное число не годится: длина `ClientHello` меняется от отпечатка к
/// отпечатку и от соединения к соединению (GREASE, `padding`), а разрезать
/// нужно всегда одно и то же место — имя узла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// Начало имени узла в расширении SNI.
    Sni,
    /// Середина домена второго уровня: `go|ogle` в `www.google.com`.
    ///
    /// `midsld` у `zapret2`. Разрез посреди самого имени ломает поиск по
    /// списку доменов даже тому DPI, который сегменты всё-таки складывает,
    /// но складывает не так, как TCP.
    MidSld,
    /// Конец имени узла.
    EndHost,
}

impl Marker {
    /// Разбирает имя ориентира.
    fn parse(name: &str) -> Option<Self> {
        match name {
            "sni" | "host" => Some(Self::Sni),
            "midsld" => Some(Self::MidSld),
            "endhost" => Some(Self::EndHost),
            _ => None,
        }
    }
}

/// Точка разреза так, как её записали в настройках.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// Смещение от начала посылки.
    Absolute(usize),
    /// Смещение от конца посылки.
    FromEnd(usize),
    /// Ориентир и сдвиг от него.
    Relative {
        /// От чего считать.
        marker: Marker,
        /// На сколько байт сдвинуться. Может быть отрицательным.
        shift: i32,
    },
}

impl Position {
    /// Разбирает запись точки: `1`, `-1`, `sni`, `sni+1`, `midsld-2`.
    pub fn parse(raw: &str) -> TransportResult<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(TransportError::config("пустая точка разреза"));
        }

        if let Some(rest) = raw.strip_prefix('-') {
            let offset = parse_offset(rest)?;
            return Ok(Self::FromEnd(offset));
        }
        if raw.as_bytes()[0].is_ascii_digit() {
            return Ok(Self::Absolute(parse_offset(raw)?));
        }

        // Ориентир со сдвигом: имя до `+`/`-`, число после.
        let split = raw.find(['+', '-']).unwrap_or(raw.len());
        let (name, tail) = raw.split_at(split);
        let marker = Marker::parse(name).ok_or_else(|| {
            TransportError::config(format!(
                "неизвестная точка разреза `{raw}`: бывают число, -число, sni, midsld, endhost"
            ))
        })?;
        let shift = if tail.is_empty() {
            0
        } else {
            tail.parse::<i32>()
                .map_err(|_| TransportError::config(format!("сдвиг `{tail}` — не число")))?
        };
        Ok(Self::Relative { marker, shift })
    }

    /// Куда точка попадает в посылке длиной `len`, если имя узла найдено в
    /// `host_at`.
    ///
    /// `None` — точка вне посылки либо ориентира в ней нет. Это не ошибка:
    /// имени узла в посылке может не быть вовсе, и разрез просто не делается.
    pub fn resolve(&self, len: usize, host_at: Option<(usize, usize)>) -> Option<usize> {
        let raw = match *self {
            Self::Absolute(offset) => i64::try_from(offset).ok()?,
            Self::FromEnd(offset) => i64::try_from(len).ok()? - i64::try_from(offset).ok()?,
            Self::Relative { marker, shift } => {
                let (start, host_len) = host_at?;
                let base = match marker {
                    Marker::Sni => start,
                    Marker::MidSld => start + sld_middle(host_len),
                    Marker::EndHost => start + host_len,
                };
                i64::try_from(base).ok()? + i64::from(shift)
            }
        };

        // Разрез в нуле и в конце посылки — это отсутствие разреза: он не
        // создаёт второго сегмента, зато создаёт лишний системный вызов.
        let raw = usize::try_from(raw).ok()?;
        (raw > 0 && raw < len).then_some(raw)
    }
}

/// Середина имени узла — не строки целиком, а его значащей части.
///
/// У `www.google.com` это середина `google`, а не середина всей строки: DPI
/// ищет в списке домен, и разрезать нужно его.
fn sld_middle(host_len: usize) -> usize {
    host_len / 2
}

fn parse_offset(raw: &str) -> TransportResult<usize> {
    raw.parse::<usize>()
        .map_err(|_| TransportError::config(format!("смещение `{raw}` — не число")))
}

/// Настройки рассинхронизации так, как они лежат в профиле.
///
/// Отдельная структура с `serde`, а не поля протокола: раздел одинаков для
/// любого протокола, который однажды захочет обходить DPI своей первой
/// посылкой, и разъехаться двум его копиям нельзя.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DesyncConfig {
    /// Стратегия: `none`, `multisplit`, `disorder`, `fake`, `fakedsplit`.
    pub strategy: String,
    /// Точки разреза: `["1", "midsld", "-1"]`.
    ///
    /// Пусто у режущей стратегии — берётся `["midsld"]`: разрез посреди имени
    /// узла ломает больше всего разборов и не зависит от длины посылки.
    pub split_pos: Vec<String>,
    /// TTL ложной посылки. Ноль — [`DEFAULT_FAKE_TTL`].
    pub ttl: u8,
    /// Пауза между кусками, миллисекунды.
    ///
    /// Ноль почти всегда достаточен: куски и так уходят разными сегментами
    /// (`TCP_NODELAY`). Пауза нужна тому DPI, который склеивает сегменты,
    /// пришедшие в одном окне.
    pub delay_ms: u64,
    /// Сколько раз повторить ложную посылку.
    pub repeats: u8,
}

impl Default for DesyncConfig {
    fn default() -> Self {
        Self {
            strategy: Strategy::None.name().to_owned(),
            split_pos: Vec::new(),
            ttl: 0,
            delay_ms: 0,
            repeats: 1,
        }
    }
}

impl DesyncConfig {
    /// Проверяет и превращает настройки в готовый план.
    pub fn compile(&self) -> TransportResult<Desync> {
        let strategy = Strategy::parse(&self.strategy).ok_or_else(|| {
            TransportError::config(format!(
                "неизвестная стратегия обхода `{}`: бывают none, multisplit, disorder, fake, fakedsplit",
                self.strategy
            ))
        })?;

        let mut positions = Vec::new();
        for raw in &self.split_pos {
            positions.push(Position::parse(raw)?);
        }
        if positions.len() > MAX_SPLITS {
            return Err(TransportError::config(format!(
                "точек разреза {}, а больше {MAX_SPLITS} не бывает",
                positions.len()
            )));
        }
        if positions.is_empty() && strategy.splits() {
            positions.push(Position::Relative {
                marker: Marker::MidSld,
                shift: 0,
            });
        }
        if !positions.is_empty() && !strategy.splits() {
            return Err(TransportError::config(format!(
                "стратегия `{}` не режет посылку: точки разреза ей некуда приложить",
                strategy.name()
            )));
        }
        if self.repeats == 0 && strategy.fakes() {
            return Err(TransportError::config(
                "ложная посылка повторяется ноль раз: это стратегия `none`, а не `fake`",
            ));
        }

        Ok(Desync {
            strategy,
            positions,
            ttl: if self.ttl == 0 {
                DEFAULT_FAKE_TTL
            } else {
                self.ttl
            },
            delay: Duration::from_millis(self.delay_ms),
            repeats: self.repeats.max(1),
        })
    }
}

/// Проверенный план рассинхронизации.
#[derive(Debug, Clone)]
pub struct Desync {
    strategy: Strategy,
    positions: Vec<Position>,
    ttl: u8,
    delay: Duration,
    repeats: u8,
}

impl Desync {
    /// План, который ничего не делает.
    pub fn disabled() -> Self {
        Self {
            strategy: Strategy::None,
            positions: Vec::new(),
            ttl: DEFAULT_FAKE_TTL,
            delay: Duration::ZERO,
            repeats: 1,
        }
    }

    /// Стратегия плана.
    pub fn strategy(&self) -> Strategy {
        self.strategy
    }

    /// План ничего не меняет в отправке.
    pub fn is_disabled(&self) -> bool {
        self.strategy == Strategy::None
    }

    /// TTL ложной посылки.
    pub fn ttl(&self) -> u32 {
        u32::from(self.ttl)
    }

    /// Пауза между кусками.
    pub fn delay(&self) -> Duration {
        self.delay
    }

    /// Сколько раз повторяется ложная посылка.
    pub fn repeats(&self) -> u8 {
        self.repeats
    }

    /// Нужна ли плану ложная посылка.
    pub fn wants_fake(&self) -> bool {
        self.strategy.fakes()
    }

    /// Границы кусков для посылки длиной `len`.
    ///
    /// `host` — имя узла, если оно в посылке есть: по нему считаются
    /// ориентиры. Результат упорядочен, без повторов и без нулей.
    pub fn cuts(&self, payload: &[u8], host: Option<&str>) -> Vec<usize> {
        let host_at = host.and_then(|host| find_host(payload, host));
        let mut cuts: Vec<usize> = self
            .positions
            .iter()
            .filter_map(|position| position.resolve(payload.len(), host_at))
            .collect();
        cuts.sort_unstable();
        cuts.dedup();
        cuts
    }
}

/// Ищет имя узла в посылке. Возвращает смещение и длину.
///
/// Поиск по байтам, а не разбор `ClientHello`: имя приходит сюда из настроек,
/// и найти его в собранном сообщении дешевле и надёжнее, чем повторять здесь
/// разбор расширений, который уже есть в `penguin-utls`. Ищется последнее
/// вхождение: короткое имя вроде `t.co` может случайно встретиться в
/// случайных байтах `random`, а настоящее SNI лежит в расширениях, то есть
/// дальше всех.
fn find_host(payload: &[u8], host: &str) -> Option<(usize, usize)> {
    let needle = host.as_bytes();
    if needle.is_empty() || needle.len() > payload.len() {
        return None;
    }
    payload
        .windows(needle.len())
        .rposition(|window| window == needle)
        .map(|start| (start, needle.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(strategy: &str, split: &[&str]) -> DesyncConfig {
        DesyncConfig {
            strategy: strategy.to_owned(),
            split_pos: split.iter().map(|s| (*s).to_owned()).collect(),
            ..DesyncConfig::default()
        }
    }

    #[test]
    fn every_strategy_name_survives_the_round_trip() {
        for strategy in [
            Strategy::None,
            Strategy::Multisplit,
            Strategy::Disorder,
            Strategy::Fake,
            Strategy::FakedSplit,
        ] {
            assert_eq!(Strategy::parse(strategy.name()), Some(strategy));
        }
    }

    #[test]
    fn an_unknown_strategy_is_not_silently_none() {
        // Опечатка в имени означала бы соединение без обхода там, где обход
        // включали намеренно, — и разбираться человек будет с провайдером.
        assert!(Strategy::parse("multi-split").is_none());
        assert!(config("multi-split", &[]).compile().is_err());
    }

    #[test]
    fn positions_parse_in_every_notation() {
        assert_eq!(Position::parse("3").expect("число"), Position::Absolute(3));
        assert_eq!(
            Position::parse("-2").expect("с конца"),
            Position::FromEnd(2)
        );
        assert_eq!(
            Position::parse("sni").expect("ориентир"),
            Position::Relative {
                marker: Marker::Sni,
                shift: 0
            }
        );
        assert_eq!(
            Position::parse("midsld+1").expect("ориентир со сдвигом"),
            Position::Relative {
                marker: Marker::MidSld,
                shift: 1
            }
        );
        assert_eq!(
            Position::parse("endhost-4").expect("ориентир со сдвигом назад"),
            Position::Relative {
                marker: Marker::EndHost,
                shift: -4
            }
        );
        assert!(Position::parse("sni*2").is_err());
        assert!(Position::parse("").is_err());
    }

    #[test]
    fn a_cut_outside_the_payload_is_dropped_instead_of_panicking() {
        // Точка `-100` в посылке на десять байт — обычное дело при коротком
        // приветствии, и падать из-за неё нельзя.
        assert_eq!(Position::FromEnd(100).resolve(10, None), None);
        assert_eq!(Position::Absolute(10).resolve(10, None), None);
        assert_eq!(Position::Absolute(0).resolve(10, None), None);
        assert_eq!(Position::Absolute(4).resolve(10, None), Some(4));
    }

    #[test]
    fn markers_are_measured_from_the_host_inside_the_payload() {
        let mut payload = vec![0u8; 20];
        payload.extend_from_slice(b"www.google.com");
        payload.extend_from_slice(&[0u8; 5]);

        let desync = config("multisplit", &["sni", "midsld", "endhost"])
            .compile()
            .expect("настройки верны");
        let cuts = desync.cuts(&payload, Some("www.google.com"));
        // Начало имени, его середина и конец — три разных места.
        assert_eq!(cuts, vec![20, 27, 34]);
    }

    #[test]
    fn a_missing_host_leaves_the_payload_whole() {
        // Имени в посылке нет — резать нечего, и выдумывать место нельзя.
        let desync = config("multisplit", &["midsld"])
            .compile()
            .expect("настройки верны");
        assert!(desync.cuts(&[0u8; 40], Some("www.google.com")).is_empty());
        assert!(desync.cuts(&[0u8; 40], None).is_empty());
    }

    #[test]
    fn cuts_are_sorted_and_do_not_repeat() {
        // Две одинаковые точки означали бы кусок нулевой длины, то есть
        // `write` без единого байта.
        let desync = config("multisplit", &["5", "2", "5"])
            .compile()
            .expect("настройки верны");
        assert_eq!(desync.cuts(&[0u8; 10], None), vec![2, 5]);
    }

    #[test]
    fn a_splitting_strategy_without_positions_gets_the_middle_of_the_name() {
        let desync = config("multisplit", &[])
            .compile()
            .expect("настройки верны");
        let mut payload = vec![0u8; 4];
        payload.extend_from_slice(b"example.com");
        assert_eq!(desync.cuts(&payload, Some("example.com")), vec![4 + 5]);
    }

    #[test]
    fn positions_without_a_splitting_strategy_are_refused() {
        // Молчаливое игнорирование настройки — это профиль, который выглядит
        // настроенным и работает не так, как написано.
        assert!(config("fake", &["2"]).compile().is_err());
        assert!(config("none", &["2"]).compile().is_err());
    }

    #[test]
    fn the_ttl_is_never_zero() {
        // TTL, равный нулю, означает пакет, который не покидает машину.
        let plan = config("fake", &[]).compile().expect("настройки верны");
        assert_eq!(plan.ttl(), u32::from(DEFAULT_FAKE_TTL));

        let plan = DesyncConfig {
            ttl: 7,
            ..config("fake", &[])
        }
        .compile()
        .expect("настройки верны");
        assert_eq!(plan.ttl(), 7);
    }

    #[test]
    fn too_many_cuts_are_refused() {
        let many: Vec<String> = (1..=MAX_SPLITS + 1).map(|i| i.to_string()).collect();
        let config = DesyncConfig {
            strategy: "multisplit".to_owned(),
            split_pos: many,
            ..DesyncConfig::default()
        };
        assert!(config.compile().is_err());
    }

    #[test]
    fn the_default_config_does_nothing() {
        // Обход включают намеренно: сам по себе он лишние пакеты и лишний
        // повод для сети вести себя странно.
        let plan = DesyncConfig::default().compile().expect("настройки верны");
        assert!(plan.is_disabled());
        assert!(!plan.wants_fake());
    }

    #[test]
    fn the_host_is_found_by_its_last_occurrence() {
        // Короткое имя может случайно встретиться в случайных байтах головы
        // сообщения; настоящее SNI лежит в расширениях, то есть дальше.
        let mut payload = b"t.co".to_vec();
        payload.extend_from_slice(&[0u8; 10]);
        payload.extend_from_slice(b"t.co");
        assert_eq!(find_host(&payload, "t.co"), Some((14, 4)));
    }
}
