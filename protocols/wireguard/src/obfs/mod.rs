//! AmneziaWG: обфускация поверх WireGuard. v1/v2 — junk-пакеты, padding и
//! магические заголовки (`Jc`/`Jmin`/`Jmax`, `S1`–`S4`, `H1`–`H4`); 1.5/3 —
//! сигнатуры `I1`–`I5`, защита заголовков (`header_protection_key`), хвосты
//! (`random_trailers`) и добавка к содержимому (`content_padding_addition`).
//! При нулевых значениях и заголовках 1–4 протокол сводится к обычному WireGuard.
//!
//! `params` разбирает конфигурацию, `engine` обёртывает и распознаёт кадры,
//! `protect`, `chain` и `padding` — части AWG 3. Таймеры AWG 3
//! (`rekey_after_time` и прочие) — местная политика клиента, а не обфускация:
//! не поддержаны и отклоняются [`AmneziaParams::validate`].

mod chain;
mod engine;
mod padding;
mod params;
mod protect;

pub use engine::{Classified, MsgKind, Obfuscation};
pub use params::AmneziaParams;
