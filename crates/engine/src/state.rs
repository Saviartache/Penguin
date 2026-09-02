//! Автомат состояний тоннеля и переходы между ними.
//!
//! Состояние живёт в [`penguin_core::state::TunnelState`] — его видит и
//! интерфейс. Здесь остаётся то, что относится к переходам: какие из них
//! законны и что при этом происходит.
//!
//! ```text
//!   Disconnected ──connect──► Connecting ──► Connected
//!        ▲                        │             │
//!        │                        │ ошибка      │ обрыв
//!        │                        ▼             ▼
//!        └──── Disconnecting ◄── Failed ◄── Reconnecting
//! ```
//!
//! Смысл автомата не в педантизме. Без него в коде заводятся булевы флаги,
//! которые рано или поздно оказываются выставлены оба сразу — и интерфейс
//! показывает то ли «подключено», то ли «подключаюсь», в зависимости от
//! того, какой флаг проверили первым.

use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use penguin_core::id::ProfileId;
use penguin_core::state::TunnelState;

use crate::events::{Event, EventBus};

/// Состояние тоннеля с уведомлением о переходах.
#[derive(Debug)]
pub struct StateMachine {
    state: ArcSwap<TunnelState>,
    /// Когда установилось текущее соединение.
    connected_at: ArcSwap<Option<Instant>>,
    events: EventBus,
}

impl StateMachine {
    /// Заводит автомат в состоянии «отключён».
    pub fn new(events: EventBus) -> Self {
        Self {
            state: ArcSwap::from_pointee(TunnelState::Disconnected),
            connected_at: ArcSwap::from_pointee(None),
            events,
        }
    }

    /// Текущее состояние.
    ///
    /// Время работы считается на месте, а не хранится: иначе его пришлось бы
    /// обновлять по таймеру, а часы у демона и у интерфейса всё равно разные.
    pub fn current(&self) -> TunnelState {
        let state = (**self.state.load()).clone();
        match state {
            TunnelState::Connected { profile, .. } => {
                let uptime_secs = self
                    .connected_at
                    .load()
                    .map_or(0, |since| since.elapsed().as_secs());
                TunnelState::Connected {
                    profile,
                    uptime_secs,
                }
            }
            other => other,
        }
    }

    /// Переходит в новое состояние и сообщает об этом.
    pub fn set(&self, state: TunnelState) {
        // Момент установления запоминается ровно один раз: переход
        // `Connected -> Connected` бывает при обновлении счётчиков, и
        // сбрасывать им время работы нельзя.
        match (&state, &**self.state.load()) {
            (TunnelState::Connected { .. }, TunnelState::Connected { .. }) => {}
            (TunnelState::Connected { .. }, _) => {
                self.connected_at.store(Arc::new(Some(Instant::now())));
            }
            _ => self.connected_at.store(Arc::new(None)),
        }

        self.state.store(Arc::new(state));
        self.events.emit(Event::State {
            state: self.current(),
        });
    }

    /// Переход «подключаемся».
    pub fn connecting(&self, profile: ProfileId) {
        self.set(TunnelState::Connecting { profile });
    }

    /// Переход «подключено».
    pub fn connected(&self, profile: ProfileId) {
        self.set(TunnelState::Connected {
            profile,
            uptime_secs: 0,
        });
    }

    /// Переход «переподключаемся».
    pub fn reconnecting(&self, profile: ProfileId, attempt: u32, reason: impl Into<String>) {
        self.set(TunnelState::Reconnecting {
            profile,
            attempt,
            reason: reason.into(),
        });
    }

    /// Переход «сломалось насовсем».
    pub fn failed(&self, reason: impl Into<String>) {
        self.set(TunnelState::Failed {
            reason: reason.into(),
        });
    }

    /// Переход «отключено».
    pub fn disconnected(&self) {
        self.set(TunnelState::Disconnected);
    }

    /// Тоннель работает.
    pub fn is_active(&self) -> bool {
        self.state.load().is_active()
    }

    /// Идёт переключение.
    pub fn is_busy(&self) -> bool {
        self.state.load().is_busy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> (StateMachine, tokio::sync::broadcast::Receiver<Event>) {
        let events = EventBus::new();
        let receiver = events.subscribe();
        (StateMachine::new(events), receiver)
    }

    #[test]
    fn starts_disconnected() {
        let (machine, _events) = machine();
        assert_eq!(machine.current(), TunnelState::Disconnected);
        assert!(!machine.is_active());
        assert!(!machine.is_busy());
    }

    #[tokio::test]
    async fn every_transition_is_announced() {
        // Интерфейс подписан, а не опрашивает: пропущенный переход означает
        // окно, застрявшее в прежнем состоянии.
        let (machine, mut events) = machine();

        machine.connecting(ProfileId::new("home"));
        assert!(matches!(
            events.recv().await.expect("событие"),
            Event::State {
                state: TunnelState::Connecting { .. }
            }
        ));

        machine.connected(ProfileId::new("home"));
        assert!(matches!(
            events.recv().await.expect("событие"),
            Event::State {
                state: TunnelState::Connected { .. }
            }
        ));
    }

    #[test]
    fn connected_reports_uptime() {
        let (machine, _events) = machine();
        machine.connected(ProfileId::new("home"));

        assert!(machine.is_active());
        let TunnelState::Connected { uptime_secs, .. } = machine.current() else {
            panic!("ожидалось подключённое состояние");
        };
        // Время работы считается на месте; сразу после подключения оно нулевое.
        assert_eq!(uptime_secs, 0);
    }

    #[test]
    fn repeated_connected_does_not_reset_uptime() {
        // Переход `Connected -> Connected` бывает при обновлении счётчиков.
        let (machine, _events) = machine();
        machine.connected(ProfileId::new("home"));
        let first = machine.connected_at.load().expect("момент запомнен");

        machine.connected(ProfileId::new("home"));
        assert_eq!(machine.connected_at.load().expect("момент на месте"), first);
    }

    #[test]
    fn disconnect_clears_uptime() {
        let (machine, _events) = machine();
        machine.connected(ProfileId::new("home"));
        machine.disconnected();
        assert!(machine.connected_at.load().is_none());
    }

    #[test]
    fn busy_states_are_recognised() {
        let (machine, _events) = machine();

        machine.connecting(ProfileId::new("home"));
        assert!(machine.is_busy());

        machine.reconnecting(ProfileId::new("home"), 3, "сеть пропала");
        assert!(machine.is_busy());
        assert!(!machine.is_active());

        machine.failed("неверный пароль");
        assert!(!machine.is_busy());
        assert!(!machine.is_active());
    }

    #[test]
    fn failure_carries_the_reason() {
        let (machine, _events) = machine();
        machine.failed("сервер отклонил аутентификацию");

        let TunnelState::Failed { reason } = machine.current() else {
            panic!("ожидалась ошибка");
        };
        assert!(reason.contains("аутентификацию"));
    }
}
