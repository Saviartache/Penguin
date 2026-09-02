//! События: смена состояния, скорость, строка журнала, решение маршрутизатора.
//!
//! Своя копия события, а не переэкспорт того, что определено в движке. Причина
//! в направлении зависимостей: канал управления лежит ниже движка по графу и
//! знать о нём не может. Но причина глубже — это **формат провода**, и он
//! обязан меняться медленнее, чем внутреннее устройство движка.

use penguin_core::state::TunnelState;
use penguin_core::stats::{Throughput, Traffic};
use serde::{Deserialize, Serialize};

/// Что произошло.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "event")]
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

    /// Строка журнала.
    Log {
        /// Насколько это важно.
        level: LogLevel,
        /// Текст.
        message: String,
    },

    /// Решение по соединению.
    Decision {
        /// Куда шло соединение.
        target: String,
        /// Какое приложение.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        process: Option<String>,
        /// Что решено.
        decision: String,
        /// Сработавшее правило.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule: Option<String>,
    },

    /// Правила пересобраны.
    RulesReloaded {
        /// Сколько правил получилось.
        count: usize,
    },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_json() {
        let events = [
            Event::State {
                state: TunnelState::Disconnected,
            },
            Event::Throughput {
                rate: Throughput::default(),
                total: Traffic::default(),
                connections: 7,
            },
            Event::Log {
                level: LogLevel::Warning,
                message: "сеть пропала".to_owned(),
            },
            Event::Decision {
                target: "example.com:443".to_owned(),
                process: Some("chrome.exe".to_owned()),
                decision: "напрямую".to_owned(),
                rule: Some("games".to_owned()),
            },
            Event::RulesReloaded { count: 3 },
        ];

        for event in events {
            let json = serde_json::to_string(&event).expect("сериализуется");
            let back: Event = serde_json::from_str(&json).expect("разбирается");
            assert_eq!(back, event);
        }
    }

    #[test]
    fn optional_fields_may_be_absent() {
        // Старая сторона канала пришлёт событие без новых полей; разобрать
        // его всё равно надо.
        let json = r#"{"event":"decision","target":"a:1","decision":"в тоннель"}"#;
        let event: Event = serde_json::from_str(json).expect("разбирается");
        assert!(matches!(
            event,
            Event::Decision {
                process: None,
                rule: None,
                ..
            }
        ));
    }
}
