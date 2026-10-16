//! Настройки рассинхронизации и то, во что они превращаются перед отправкой.
//!
//! Чистая логика: ни сокета, ни ожидания.

use std::ops::Range;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{TransportError, TransportResult};

/// TTL ложной посылки, когда его не задали.
///
/// Три перехода: дальше DPI провайдера, ближе сервера. Ноль нельзя: пакет не уйдёт с машины.
pub const DEFAULT_FAKE_TTL: u8 = 3;

/// TTL обычных пакетов — на случай, если его не спросить у сокета.
pub const DEFAULT_TTL: u32 = 64;

/// Пауза после куска с подменённым TTL — окно, за которое он успевает уйти.
///
/// Ядро читает TTL в момент отправки пакета, не записи.
pub const FOOLING_PAUSE: Duration = Duration::from_millis(1);

/// Сколько кусков разреза допускается.
const MAX_SPLITS: usize = 8;

/// Чем ломается сборка потока у DPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Strategy {
    /// Ничего не делать: первая посылка уходит одним куском.
    #[default]
    None,
    /// Разрезать посылку на куски и отправить их по порядку.
    ///
    /// `multisplit` у `zapret2`.
    Multisplit,
    /// Разрезать и отправить не по порядку.
    ///
    /// `multidisorder` у `zapret2`: первый кусок с малым TTL, ядро повторит его позже.
    Disorder,
    /// Отправить перед настоящей посылкой ложную с малым TTL.
    ///
    /// `fake` у `zapret2`.
    Fake,
    /// Ложная посылка и разрез сразу.
    ///
    /// `fakedsplit` у `zapret2`.
    FakedSplit,
}

impl Strategy {
    /// Разбирает имя стратегии из настроек.
    ///
    /// Пустая строка — `none`.
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
/// Длина `ClientHello` плавает (GREASE, `padding`), а резать надо всегда имя узла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// Начало имени узла в расширении SNI.
    Sni,
    /// Середина домена второго уровня: `go|ogle` в `www.google.com`.
    ///
    /// `midsld` у `zapret2`.
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

    /// Позиция точки в посылке длиной `len`; `host_at` — найденное имя узла.
    ///
    /// `None` — точка вне посылки или ориентира нет.
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

        let raw = usize::try_from(raw).ok()?;
        (raw > 0 && raw < len).then_some(raw)
    }
}

/// Середина значащей части имени: у `www.google.com` — середина `google`.
fn sld_middle(host_len: usize) -> usize {
    host_len / 2
}

fn parse_offset(raw: &str) -> TransportResult<usize> {
    raw.parse::<usize>()
        .map_err(|_| TransportError::config(format!("смещение `{raw}` — не число")))
}

/// Настройки рассинхронизации так, как они лежат в профиле.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DesyncConfig {
    /// Стратегия: `none`, `multisplit`, `disorder`, `fake`, `fakedsplit`.
    pub strategy: String,
    /// Точки разреза: `["1", "midsld", "-1"]`.
    ///
    /// Пусто у режущей стратегии — `["midsld"]`.
    pub split_pos: Vec<String>,
    /// TTL ложной посылки. Ноль — [`DEFAULT_FAKE_TTL`].
    pub ttl: u8,
    /// Пауза между кусками, миллисекунды.
    ///
    /// Нужна DPI, склеивающему сегменты одного окна.
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

/// Шаг отправки первой посылки.
///
/// Не зависит от исполнителя: `async` ([`crate::desync::write`]) или `poll_write`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Понизить TTL исходящих пакетов до [`Desync::ttl`].
    Fool,
    /// Вернуть TTL, с которым сокет пришёл.
    Restore,
    /// Отправить ложную посылку целиком.
    Decoy,
    /// Отправить кусок настоящей посылки.
    Chunk(Range<usize>),
    /// Подождать.
    Pause(Duration),
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
    /// `host` — имя узла для ориентиров. Результат упорядочен, без повторов и нулей.
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

    /// Во что превращается отправка посылки по этому плану.
    ///
    /// `decoy` — есть ли ложная посылка; нет — шагов с ней не будет. Пустых кусков нет.
    pub fn steps(&self, payload: &[u8], host: Option<&str>, decoy: bool) -> Vec<Step> {
        let mut steps = Vec::new();

        if self.wants_fake() && decoy {
            steps.push(Step::Fool);
            for _ in 0..self.repeats {
                steps.push(Step::Decoy);
            }
            steps.push(Step::Pause(FOOLING_PAUSE));
            steps.push(Step::Restore);
        }

        let pieces = ranges(payload.len(), &self.cuts(payload, host));
        for (index, piece) in pieces.iter().enumerate() {
            let fooled = self.strategy == Strategy::Disorder && index == 0 && pieces.len() > 1;
            if fooled {
                steps.push(Step::Fool);
            }
            steps.push(Step::Chunk(piece.clone()));
            if fooled {
                steps.push(Step::Pause(FOOLING_PAUSE));
                steps.push(Step::Restore);
            } else if !self.delay.is_zero() && index + 1 < pieces.len() {
                steps.push(Step::Pause(self.delay));
            }
        }
        steps
    }
}

/// Границы кусков посылки длиной `len`.
///
/// Точки упорядочены и внутри посылки ([`Desync::cuts`]). Пустой список — один кусок.
fn ranges(len: usize, cuts: &[usize]) -> Vec<Range<usize>> {
    let mut pieces = Vec::with_capacity(cuts.len() + 1);
    let mut previous = 0;
    for &cut in cuts {
        if cut <= previous || cut >= len {
            continue;
        }
        pieces.push(previous..cut);
        previous = cut;
    }
    if previous < len {
        pieces.push(previous..len);
    }
    pieces
}

/// Ищет имя узла в посылке. Возвращает смещение и длину.
///
/// Поиск по байтам; берётся последнее вхождение (SNI лежит в расширениях, после `random`).
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
        assert_eq!(cuts, vec![20, 27, 34]);
    }

    #[test]
    fn a_missing_host_leaves_the_payload_whole() {
        let desync = config("multisplit", &["midsld"])
            .compile()
            .expect("настройки верны");
        assert!(desync.cuts(&[0u8; 40], Some("www.google.com")).is_empty());
        assert!(desync.cuts(&[0u8; 40], None).is_empty());
    }

    #[test]
    fn cuts_are_sorted_and_do_not_repeat() {
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
        assert!(config("fake", &["2"]).compile().is_err());
        assert!(config("none", &["2"]).compile().is_err());
    }

    #[test]
    fn the_ttl_is_never_zero() {
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
        let plan = DesyncConfig::default().compile().expect("настройки верны");
        assert!(plan.is_disabled());
        assert!(!plan.wants_fake());
    }

    #[test]
    fn the_pieces_go_in_order_and_none_of_them_is_empty() {
        for cuts in [vec![], vec![0], vec![5], vec![0, 5, 5, 5], vec![9]] {
            let pieces = ranges(5, &cuts);
            assert!(pieces.iter().all(|piece| !piece.is_empty()), "{cuts:?}");
            assert_eq!(pieces.last().map(|piece| piece.end), Some(5), "{cuts:?}");
        }
        assert_eq!(ranges(5, &[2, 4]), vec![0..2, 2..4, 4..5]);
        assert!(ranges(0, &[]).is_empty(), "пустую посылку резать не на что");
    }

    #[test]
    fn disorder_fools_the_first_piece_and_puts_the_ttl_back() {
        let plan = config("disorder", &["2"])
            .compile()
            .expect("настройки верны");
        assert_eq!(
            plan.steps(b"hello", None, false),
            vec![
                Step::Fool,
                Step::Chunk(0..2),
                Step::Pause(FOOLING_PAUSE),
                Step::Restore,
                Step::Chunk(2..5),
            ]
        );
    }

    #[test]
    fn a_single_piece_is_never_fooled() {
        let plan = config("disorder", &["99"])
            .compile()
            .expect("настройки верны");
        assert_eq!(plan.steps(b"hello", None, false), vec![Step::Chunk(0..5)]);
    }

    #[test]
    fn the_fake_steps_appear_only_when_there_is_something_to_send() {
        let plan = config("fake", &[]).compile().expect("настройки верны");
        assert_eq!(
            plan.steps(b"real", None, true),
            vec![
                Step::Fool,
                Step::Decoy,
                Step::Pause(FOOLING_PAUSE),
                Step::Restore,
                Step::Chunk(0..4),
            ]
        );
        assert_eq!(plan.steps(b"real", None, false), vec![Step::Chunk(0..4)]);
    }

    #[test]
    fn the_pause_between_pieces_is_asked_for_only_between_them() {
        let plan = DesyncConfig {
            delay_ms: 5,
            ..config("multisplit", &["2"])
        }
        .compile()
        .expect("настройки верны");
        assert_eq!(
            plan.steps(b"hello", None, false),
            vec![
                Step::Chunk(0..2),
                Step::Pause(Duration::from_millis(5)),
                Step::Chunk(2..5),
            ]
        );
    }

    #[test]
    fn the_host_is_found_by_its_last_occurrence() {
        let mut payload = b"t.co".to_vec();
        payload.extend_from_slice(&[0u8; 10]);
        payload.extend_from_slice(b"t.co");
        assert_eq!(find_host(&payload, "t.co"), Some((14, 4)));
    }
}
