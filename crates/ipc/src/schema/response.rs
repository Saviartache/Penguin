//! Ответы и ошибки.

use penguin_config::RootConfig;
use penguin_core::state::TunnelState;
use penguin_core::stats::{Rtt, Throughput, Traffic};
use serde::{Deserialize, Serialize};

/// Что ответил демон.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "response")]
pub enum Response {
    /// Готово, сказать нечего.
    Ok,

    /// Демон жив.
    Pong {
        /// Версия демона.
        ///
        /// Интерфейс сравнивает её со своей: разные версии по разные стороны
        /// канала — обычное дело после обновления, когда служба ещё старая.
        version: String,

        /// Отпечаток файла, с которым служба была запущена.
        ///
        /// Версии на это не хватает: между сборками она не меняется, а файл
        /// меняется. Служба же держит в памяти тот образ, с которым её
        /// запустили, — положить рядом новый файл мало.
        ///
        /// Пустая строка означает старую службу, которая отпечатка не знает.
        #[serde(default)]
        build: String,
    },

    /// Состояние тоннеля.
    Status(Box<StatusReport>),

    /// Настройки.
    Config(Box<RootConfig>),

    /// Объяснение решения.
    Explanation(Box<Explanation>),

    /// Список приложений.
    Processes {
        /// Что запущено.
        apps: Vec<AppInfo>,
    },

    /// Задержки до профилей.
    Probes {
        /// Результаты.
        results: Vec<ProbeResult>,
    },

    /// Не получилось.
    Error {
        /// Что сказать пользователю.
        message: String,
        /// Нужно ли ему что-то сделать, прежде чем повторять.
        ///
        /// По этому признаку интерфейс решает, показывать ли
        /// «переподключаюсь» или «исправьте настройки».
        needs_user_action: bool,
    },
}

impl Response {
    /// Ответ об ошибке.
    pub fn error(message: impl std::fmt::Display, needs_user_action: bool) -> Self {
        Self::Error {
            message: message.to_string(),
            needs_user_action,
        }
    }

    /// Это ошибка.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }
}

/// Полное состояние клиента.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReport {
    /// Состояние тоннеля.
    pub state: TunnelState,
    /// Счётчики с начала сеанса.
    pub traffic: Traffic,
    /// Мгновенная скорость.
    pub rate: Throughput,
    /// Сколько соединений открыто прямо сейчас.
    pub connections: u64,
    /// Сколько правил в наборе.
    pub rules: usize,
    /// Режим тоннелирования.
    pub mode: String,
    /// Задержка до сервера, если известна.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt: Option<Rtt>,
}

/// Разбор одного правила при проверке.
///
/// Своя копия, а не переэкспорт типа из маршрутизатора: канал управления
/// лежит ниже него по графу зависимостей, и — что важнее — это формат
/// провода, который обязан меняться медленнее внутреннего устройства.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleTrace {
    /// Идентификатор правила.
    pub id: String,
    /// Имя правила.
    pub name: String,
    /// Условие, записанное словами.
    pub condition: String,
    /// Подошло ли.
    pub matched: bool,
    /// Это правило и дало решение.
    pub decisive: bool,
}

/// Результат проверки правил.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    /// Что получилось.
    pub decision: String,
    /// Отчего.
    pub reason: String,
    /// Все правила по порядку разбора.
    pub rules: Vec<RuleTrace>,
}

/// Запущенное приложение.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInfo {
    /// Полный путь.
    pub path: String,
    /// Имя файла.
    pub name: String,
    /// Сколько процессов запущено.
    pub instances: usize,
}

/// Задержка до профиля.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Какой профиль.
    pub profile: String,
    /// Задержка в миллисекундах. `None` — не ответил.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_millis: Option<u32>,
    /// Что пошло не так.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_json() {
        let responses = [
            Response::Ok,
            Response::Pong {
                version: "0.1.0".to_owned(),
                build: "1700000000".to_owned(),
            },
            Response::error("не удалось подключиться", false),
            Response::Processes {
                apps: vec![AppInfo {
                    path: "c:/apps/app.exe".to_owned(),
                    name: "app.exe".to_owned(),
                    instances: 3,
                }],
            },
        ];

        for response in responses {
            let json = serde_json::to_string(&response).expect("сериализуется");
            let back: Response = serde_json::from_str(&json).expect("разбирается");
            assert_eq!(back, response);
        }
    }

    #[test]
    fn status_travels_whole() {
        let status = StatusReport {
            state: TunnelState::Disconnected,
            traffic: Traffic::default(),
            rate: Throughput::default(),
            connections: 0,
            rules: 3,
            mode: "full".to_owned(),
            rtt: Some(Rtt::from_millis(42)),
        };
        let response = Response::Status(Box::new(status.clone()));

        let json = serde_json::to_string(&response).expect("сериализуется");
        let Response::Status(back) = serde_json::from_str(&json).expect("разбирается")
        else {
            panic!("не то состояние");
        };
        assert_eq!(*back, status);
    }

    #[test]
    fn errors_carry_whether_the_user_must_act() {
        // По этому признаку интерфейс решает, показывать ли
        // «переподключаюсь» или «исправьте настройки».
        let response = Response::error("неверный пароль", true);
        let Response::Error {
            needs_user_action, ..
        } = response
        else {
            panic!("не та ветка");
        };
        assert!(needs_user_action);
    }

    #[test]
    fn error_is_recognisable() {
        assert!(Response::error("что-то", false).is_error());
        assert!(!Response::Ok.is_error());
    }
}
