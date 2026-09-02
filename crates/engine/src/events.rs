//! Шина событий наружу: состояние, скорость, журнал, решения маршрутизатора.
//!
//! Интерфейс не опрашивает движок — он подписывается. Разница видна на
//! графике скорости: опрос раз в секунду даёт рваную линию и лишний обмен
//! через канал управления, подписка — ровный поток.
//!
//! Канал широковещательный и **с потерями**. Подписчик, который не успевает
//! читать, пропускает часть событий, а не задерживает движок: график, на
//! котором не хватило кадра, — мелочь по сравнению с тоннелем, который встал
//! из-за неотрисованного окна.

use penguin_core::id::{OutboundId, RuleId};
use penguin_core::state::TunnelState;
use penguin_core::stats::{Throughput, Traffic};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Сколько событий держать для отставшего подписчика.
///
/// Хватает на несколько секунд обычного потока. Отстав сильнее, подписчик
/// получает сообщение о пропуске и продолжает с текущего места.
pub const CHANNEL_CAPACITY: usize = 256;

/// Что произошло.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Event {
    /// Состояние тоннеля изменилось.
    State {
        /// Новое состояние.
        state: TunnelState,
    },

    /// Очередной замер скорости.
    Throughput {
        /// Мгновенная скорость.
        rate: Throughput,
        /// Счётчики с начала сеанса.
        total: Traffic,
        /// Сколько соединений открыто прямо сейчас.
        connections: u64,
    },

    /// Строка журнала, которую стоит показать пользователю.
    Log {
        /// Насколько это важно.
        level: LogLevel,
        /// Текст.
        message: String,
    },

    /// Решение по соединению.
    ///
    /// Отправляется только когда интерфейс просит подробностей: на обычной
    /// нагрузке это сотни событий в секунду.
    Decision {
        /// Куда шло соединение.
        target: String,
        /// Какое приложение.
        process: Option<String>,
        /// Что решено.
        decision: String,
        /// Сработавшее правило, если оно было.
        rule: Option<String>,
    },

    /// Профиль сменился.
    ProfileChanged {
        /// Новое направление.
        outbound: OutboundId,
    },

    /// Правила пересобраны.
    RulesReloaded {
        /// Сколько правил получилось.
        count: usize,
    },
}

impl Event {
    /// Событие журнала.
    pub fn log(level: LogLevel, message: impl Into<String>) -> Self {
        Self::Log {
            level,
            message: message.into(),
        }
    }

    /// Событие решения.
    pub fn decision(
        target: impl Into<String>,
        process: Option<String>,
        decision: impl Into<String>,
        rule: Option<RuleId>,
    ) -> Self {
        Self::Decision {
            target: target.into(),
            process,
            decision: decision.into(),
            rule: rule.map(|id| id.to_string()),
        }
    }
}

/// Важность строки журнала.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Ход работы.
    Info,
    /// Что-то пошло не так, но работа продолжается.
    Warning,
    /// Работа прервана.
    Error,
}

/// Шина событий.
#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<Event>,
}

impl EventBus {
    /// Заводит шину.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self { sender }
    }

    /// Отправляет событие.
    ///
    /// Отсутствие подписчиков — обычное дело: интерфейс может быть закрыт, а
    /// демон работает. Ошибкой это не считается.
    pub fn emit(&self, event: Event) {
        let _ = self.sender.send(event);
    }

    /// Подписывается на события.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    /// Сколько сейчас подписчиков.
    pub fn subscribers(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn delivers_to_subscribers() {
        let bus = EventBus::new();
        let mut first = bus.subscribe();
        let mut second = bus.subscribe();

        bus.emit(Event::log(LogLevel::Info, "поехали"));

        // Широковещательный: событие получают все подписчики, а не один.
        assert!(matches!(
            first.recv().await.expect("событие"),
            Event::Log { .. }
        ));
        assert!(matches!(
            second.recv().await.expect("событие"),
            Event::Log { .. }
        ));
    }

    #[test]
    fn emitting_without_subscribers_is_fine() {
        // Интерфейс может быть закрыт, а демон работает.
        let bus = EventBus::new();
        assert_eq!(bus.subscribers(), 0);
        bus.emit(Event::log(LogLevel::Info, "никто не слышит"));
    }

    #[tokio::test]
    async fn slow_subscriber_loses_events_instead_of_blocking() {
        // График, на котором не хватило кадра, — мелочь по сравнению с
        // тоннелем, вставшим из-за неотрисованного окна.
        let bus = EventBus::new();
        let mut slow = bus.subscribe();

        for step in 0..(CHANNEL_CAPACITY * 2) {
            bus.emit(Event::log(LogLevel::Info, format!("событие {step}")));
        }

        // Первым делом отставший узнаёт, что часть событий пропущена.
        assert!(matches!(
            slow.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));
        // И продолжает читать с текущего места.
        assert!(slow.recv().await.is_ok());
    }

    #[test]
    fn events_survive_serialization() {
        // События уходят в интерфейс через канал управления.
        let event = Event::decision(
            "example.com:443",
            Some("chrome.exe".to_owned()),
            "напрямую",
            Some(RuleId::new("r1")),
        );
        let json = serde_json::to_string(&event).expect("сериализуется");
        let back: Event = serde_json::from_str(&json).expect("разбирается");
        assert_eq!(back, event);
    }

    #[test]
    fn state_events_survive_serialization() {
        let event = Event::State {
            state: TunnelState::Disconnected,
        };
        let json = serde_json::to_string(&event).expect("сериализуется");
        assert_eq!(
            serde_json::from_str::<Event>(&json).expect("разбирается"),
            event
        );
    }
}
