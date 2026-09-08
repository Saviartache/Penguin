//! Дополнение первых записей: расписание, выведенное из ключа.
//!
//! # Что оно прячет
//!
//! Длины записей открыты — как и у настоящего TLS. Начало любого прокси на
//! этом и видно: короткий запрос (адрес назначения), короткий ответ
//! (подтверждение), дальше поток. У настоящего TLS 1.3 начало выглядит иначе:
//! сертификат сервера — это килобайты, и первая запись от сервера всегда
//! большая. Дополнение приводит первые несколько записей к размерам, на
//! которые смотреть бессмысленно.
//!
//! # Почему расписание выведенное, а не табличное
//!
//! У AnyTLS схема дополнения — открытая таблица в конфигурации, одна и та же
//! у всех. Такую таблицу можно выучить: набор длин первых записей сам
//! становится отпечатком протокола.
//!
//! Здесь расписание выводится из сеансового ключа. Оно своё на каждом
//! соединении, снаружи неотличимо от случайного и при этом одинаково у обеих
//! сторон — выводить его из общего секрета дешевле, чем договариваться о нём
//! на проводе (и не создаёт ещё одного поля, которое можно искать).
//!
//! ```text
//!  запись 0   512..1535 байт      \
//!  запись 1   512..1535 байт       > длины взяты из ключа
//!  ...                            /
//!  запись 6+  без дополнения      — дальше видно только объём трафика
//! ```

use crate::wire::frame;

/// Сколько первых записей дополняются.
///
/// Шесть — это всё начало разговора: рукопожатие мультиплексора, открытие
/// первого потока и первый запрос с ответом. Дальше дополнять бессмысленно:
/// на длинном потоке видно не длины записей, а объём трафика, и его
/// дополнением не скрыть.
pub const ROUNDS: usize = 6;

/// Наименьшая длина дополненной записи.
const MIN: usize = 512;

/// Насколько длина может вырасти сверх наименьшей.
const SPREAD: usize = 1024;

/// Расписание дополнения одного направления.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Padding {
    targets: [u16; ROUNDS],
}

impl Padding {
    /// Выводит расписание из затравки.
    ///
    /// Затравку даёт ключевое расписание ([`crate::wire::keys`]): у каждого
    /// направления она своя, иначе запись клиента и ответ сервера получали бы
    /// одинаковые длины — а это отпечаток не хуже таблицы.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut targets = [0u16; ROUNDS];
        for (index, target) in targets.iter_mut().enumerate() {
            let pair = u16::from_be_bytes([seed[index * 2], seed[index * 2 + 1]]);
            let size = MIN + usize::from(pair) % SPREAD;
            *target = u16::try_from(size).unwrap_or(u16::MAX);
        }
        Self { targets }
    }

    /// Расписание, которое ничего не дополняет.
    ///
    /// Нужно ровно там, где дополнение вредно: внутри уже дополненного
    /// разговора (тесты формата) и в ранних данных, у которых своя длина
    /// задаётся приветствием.
    pub fn none() -> Self {
        Self {
            targets: [0; ROUNDS],
        }
    }

    /// До какой длины дополнять запись с номером `index`.
    ///
    /// Ноль — дополнять не надо.
    pub fn target(&self, index: usize) -> usize {
        self.targets
            .get(index)
            .map_or(0, |target| usize::from(*target))
    }
}

/// Дополняет тело записи до нужной длины кадром [`frame::PAD`].
///
/// Длина получается **не меньше** запрошенной: когда до цели остаётся меньше
/// заголовка кадра, дополнение всё равно добавляет пустой кадр — записи с
/// длиной «цель минус три» быть не должно, иначе по остатку восстанавливается
/// исходный размер.
pub fn pad(out: &mut Vec<u8>, target: usize) {
    if target == 0 || out.len() >= target {
        return;
    }
    let gap = target - out.len();
    let payload = gap.saturating_sub(frame::HEADER_LEN);
    // Кадр дополнения не носит смысла, и его содержимое никто не читает:
    // нули здесь дешевле случайных байт и снаружи всё равно не видны — тело
    // записи зашифровано целиком.
    let zeros = vec![0u8; payload.min(frame::MAX_PAYLOAD)];
    // Ошибка невозможна: длина обрезана по `MAX_PAYLOAD` строкой выше.
    // Молча пропустить дополнение всё же лучше, чем оборвать соединение.
    let _ = frame::write(out, frame::PAD, 0, &zeros);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_schedule_depends_on_its_seed() {
        // Иначе оно стало бы той самой таблицей, которую можно выучить.
        let one = Padding::from_seed(&[1u8; 32]);
        let two = Padding::from_seed(&[2u8; 32]);
        assert_ne!(one, two);
    }

    #[test]
    fn every_target_is_a_plausible_record_size() {
        let padding = Padding::from_seed(&[0x5Au8; 32]);
        for index in 0..ROUNDS {
            let target = padding.target(index);
            assert!(
                (MIN..MIN + SPREAD).contains(&target),
                "запись {index}: {target}"
            );
        }
    }

    #[test]
    fn padding_stops_after_the_beginning_of_the_conversation() {
        // Дальше видно объём трафика, а не длины записей, и дополнять его
        // означало бы платить за то, чего не спрячешь.
        let padding = Padding::from_seed(&[0x5Au8; 32]);
        assert_eq!(padding.target(ROUNDS), 0);
        assert_eq!(padding.target(1000), 0);
    }

    #[test]
    fn a_record_reaches_at_least_its_target() {
        for target in [0, 1, 8, 100, 512] {
            for start in [0usize, 1, 7, 99, 511] {
                let mut record = vec![0u8; start];
                pad(&mut record, target);
                assert!(
                    record.len() >= target || target == 0,
                    "было {start}, цель {target}, стало {}",
                    record.len()
                );
            }
        }
    }

    #[test]
    fn a_record_that_is_already_long_enough_is_left_alone() {
        // Лишний кадр в каждой записи — это лишние семь байт на каждый пакет.
        let mut record = vec![0u8; 600];
        pad(&mut record, 512);
        assert_eq!(record.len(), 600);
    }

    #[test]
    fn a_gap_smaller_than_a_header_still_adds_a_frame() {
        // Иначе по остатку восстанавливается исходная длина: «цель минус
        // три» бывает только у записи, которую не стали дополнять.
        let mut record = vec![0u8; 510];
        pad(&mut record, 512);
        assert_eq!(record.len(), 510 + frame::HEADER_LEN);
    }

    #[test]
    fn the_padding_frame_is_a_valid_frame() {
        // Собеседник разбирает запись целиком: сломанный кадр дополнения
        // оборвал бы соединение на ровном месте.
        let mut record = Vec::new();
        frame::write(&mut record, frame::DATA, 1, b"hi").expect("собирается");
        pad(&mut record, 300);

        let frames: Vec<_> = frame::Frames::new(&record)
            .map(|f| f.expect("разбирается"))
            .collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].0.cmd, frame::PAD);
        assert_eq!(record.len(), 300);
    }

    #[test]
    fn the_empty_schedule_pads_nothing() {
        let mut record = vec![0u8; 3];
        pad(&mut record, Padding::none().target(0));
        assert_eq!(record.len(), 3);
    }
}
