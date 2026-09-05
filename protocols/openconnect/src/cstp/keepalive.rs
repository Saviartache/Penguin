//! Keepalive и DPD: чистое решение «что сделать сейчас», без таймеров и сети.
//!
//! Сроки сервер называет в ответе на `CONNECT` — `X-CSTP-Keepalive` и
//! `X-CSTP-DPD`, обе в секундах (`cstp.c`, `atol` на значении заголовка).
//! Дальше поведение расходится у клиента и у сервера, и здесь воспроизведено
//! клиентское — из `openconnect/mainloop.c`, функция `keepalive_action`:
//!
//! - **Keepalive** — только «я жив», в одну сторону, к серверу. Если ничего
//!   не *отправлялось* дольше `keepalive` секунд, шлётся пустой кадр
//!   [`super::frame::KEEPALIVE`]. Ответа на него не бывает: сервер обновляет
//!   счётчик и молчит.
//! - **DPD** — проверка живости **той стороны**. Если ничего не *приходило*
//!   дольше `dpd` секунд, шлётся [`super::frame::DPD_OUT`]; не пришло ничего
//!   и через `2 × dpd` — с точки зрения клиента собеседник мёртв
//!   (`mainloop.c: KA_DPD_DEAD`, `now > last_rx + 2*dpd`). У сервера порог
//!   другой — `3 × dpd` (`ocserv/worker-vpn.c`, `DPD_MAX_TRIES`), — то есть
//!   асимметрия настоящая, а не ошибка портирования: сервер терпеливее.
//! - Повторный `DPD_OUT`, пока ответа нет, не шлётся чаще, чем раз в
//!   `dpd / 2`: иначе висящий ответ провоцирует шторм проб.
//!
//! Любое **входящее** сообщение — данные, keepalive, ответ на DPD — двигает
//! счётчик `dpd` вперёд: живость подтверждает не только ответ на пробу.

use std::time::Duration;

/// Что нужно сделать прямо сейчас.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Ничего не истекло.
    Nothing,
    /// Отправить поддерживающий кадр: от последней отправки прошло больше
    /// `keepalive` секунд.
    SendKeepalive,
    /// Отправить пробу DPD: от последнего входящего кадра прошло больше
    /// `dpd` секунд.
    SendDpdProbe,
    /// Собеседник не отвечает дольше `2 × dpd`: соединение мертво.
    PeerIsDead,
}

/// Сроки, которые назвал сервер. Оба поля — `None`, если сервер не прислал
/// соответствующий заголовок: это значит «выключено», а не «ноль секунд».
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timeouts {
    /// `X-CSTP-Keepalive`.
    pub keepalive: Option<Duration>,
    /// `X-CSTP-DPD`.
    pub dpd: Option<Duration>,
}

/// Решает, что делать, глядя только на прошедшее время.
///
/// `since_probe` — сколько прошло с последней отправленной пробы DPD, на
/// которую ещё не пришёл ответ; `None`, если проба не висит. Без этого срока
/// зависший ответ заставлял бы слать пробу на каждом тике таймера.
pub fn decide(
    timeouts: Timeouts,
    since_tx: Duration,
    since_rx: Duration,
    since_probe: Option<Duration>,
) -> Action {
    if let Some(dpd) = timeouts.dpd {
        if since_rx >= dpd.saturating_mul(2) {
            return Action::PeerIsDead;
        }
        let probe_due = since_probe.is_none_or(|elapsed| elapsed >= dpd / 2);
        if since_rx >= dpd && probe_due {
            return Action::SendDpdProbe;
        }
    }
    if let Some(keepalive) = timeouts.keepalive
        && since_tx >= keepalive
    {
        return Action::SendKeepalive;
    }
    Action::Nothing
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn timeouts() -> Timeouts {
        Timeouts {
            keepalive: Some(Duration::from_secs(20)),
            dpd: Some(Duration::from_secs(30)),
        }
    }

    #[test]
    fn nothing_happens_while_both_are_fresh() {
        let action = decide(
            timeouts(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            None,
        );
        assert_eq!(action, Action::Nothing);
    }

    #[test]
    fn silence_on_the_wire_asks_for_a_keepalive() {
        let action = decide(
            timeouts(),
            Duration::from_secs(25),
            Duration::from_secs(1),
            None,
        );
        assert_eq!(action, Action::SendKeepalive);
    }

    #[test]
    fn silence_from_the_peer_asks_for_a_probe() {
        let action = decide(
            timeouts(),
            Duration::from_secs(1),
            Duration::from_secs(31),
            None,
        );
        assert_eq!(action, Action::SendDpdProbe);
    }

    #[test]
    fn a_probe_already_outstanding_is_not_repeated_too_soon() {
        // Порог — `dpd / 2` = 15 секунд: проба, висящая 10 секунд, ещё не
        // повторяется, иначе ответ, идущий чуть дольше, вызвал бы шторм.
        let action = decide(
            timeouts(),
            Duration::from_secs(1),
            Duration::from_secs(35),
            Some(Duration::from_secs(10)),
        );
        assert_eq!(action, Action::Nothing);
    }

    #[test]
    fn an_outstanding_probe_is_retried_after_half_the_interval() {
        let action = decide(
            timeouts(),
            Duration::from_secs(1),
            Duration::from_secs(35),
            Some(Duration::from_secs(15)),
        );
        assert_eq!(action, Action::SendDpdProbe);
    }

    #[test]
    fn twice_the_interval_of_silence_means_the_peer_is_dead() {
        // Клиентский порог — `2 * dpd` (`mainloop.c`), не совпадает с
        // серверным `3 * dpd`: асимметрия из исходников, а не ошибка.
        let action = decide(
            timeouts(),
            Duration::from_secs(1),
            Duration::from_secs(60),
            None,
        );
        assert_eq!(action, Action::PeerIsDead);
    }

    #[test]
    fn death_outranks_a_pending_keepalive() {
        let action = decide(
            timeouts(),
            Duration::from_secs(99),
            Duration::from_secs(61),
            None,
        );
        assert_eq!(action, Action::PeerIsDead);
    }

    #[test]
    fn disabled_timers_never_fire() {
        // Сервер не прислал заголовок — значит выключено, а не «ноль секунд»:
        // с нулём эта же проверка сработала бы на первом тике таймера.
        let action = decide(
            Timeouts::default(),
            Duration::from_secs(10_000),
            Duration::from_secs(10_000),
            None,
        );
        assert_eq!(action, Action::Nothing);
    }
}
