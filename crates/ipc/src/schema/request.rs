//! Запросы: подключиться, отключиться, править правила, перечислить процессы.
//!
//! Каждый запрос — то, что интерфейс просит сделать демона. Демон работает с
//! правами системы, поэтому список запросов — это, по сути, список того, что
//! умеет сделать любой, кто дотянулся до канала управления. Отсюда его
//! умышленная краткость: ничего «на всякий случай» здесь нет.

use penguin_config::RootConfig;
use penguin_core::id::ProfileId;
use serde::{Deserialize, Serialize};

/// Что просят сделать.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "request")]
pub enum Request {
    /// Проверка связи.
    ///
    /// Первое, что делает интерфейс при запуске: по ответу видно, работает ли
    /// демон и той ли он версии.
    Ping,

    /// Текущее состояние тоннеля.
    Status,

    /// Поднять тоннель.
    Connect {
        /// Какой профиль. `None` — активный из настроек.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile: Option<ProfileId>,
    },

    /// Опустить тоннель.
    Disconnect,

    /// Прочитать настройки.
    GetConfig,

    /// Заменить настройки.
    ///
    /// Целиком, а не по частям: частичное обновление означало бы, что демон и
    /// интерфейс держат разные представления о настройках и однажды разойдутся.
    SetConfig {
        /// Новые настройки.
        config: Box<RootConfig>,
    },

    /// Объяснить, что случится с таким соединением.
    ///
    /// Настоящего соединения при этом не открывается: разбирается тот же
    /// набор правил тем же кодом, что и на горячем пути.
    Explain {
        /// Куда: `example.com:443`.
        destination: String,
        /// Какое приложение.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        process: Option<String>,
        /// Считать соединение UDP.
        #[serde(default)]
        udp: bool,
    },

    /// Список запущенных приложений — для выбора в интерфейсе.
    ListProcesses,

    /// Проверить задержку до профилей.
    Probe {
        /// Какой профиль. `None` — все.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile: Option<ProfileId>,
    },

    /// Подписаться на события.
    ///
    /// После этого соединение перестаёт быть «запрос — ответ» и превращается
    /// в поток событий: состояние, скорость, журнал.
    Subscribe,
}

impl Request {
    /// Меняет ли запрос состояние системы.
    ///
    /// По этому признаку демон решает, писать ли о нём в журнал: читающие
    /// запросы идут потоком от интерфейса, и журнал из них состоял бы целиком.
    pub fn is_mutating(&self) -> bool {
        matches!(
            self,
            Self::Connect { .. } | Self::Disconnect | Self::SetConfig { .. }
        )
    }

    /// Короткое имя для журнала.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Status => "status",
            Self::Connect { .. } => "connect",
            Self::Disconnect => "disconnect",
            Self::GetConfig => "get_config",
            Self::SetConfig { .. } => "set_config",
            Self::Explain { .. } => "explain",
            Self::ListProcesses => "list_processes",
            Self::Probe { .. } => "probe",
            Self::Subscribe => "subscribe",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_json() {
        let requests = [
            Request::Ping,
            Request::Status,
            Request::Connect {
                profile: Some(ProfileId::new("home")),
            },
            Request::Connect { profile: None },
            Request::Disconnect,
            Request::Explain {
                destination: "example.com:443".to_owned(),
                process: Some("chrome.exe".to_owned()),
                udp: false,
            },
            Request::Subscribe,
        ];

        for request in requests {
            let json = serde_json::to_string(&request).expect("сериализуется");
            let back: Request = serde_json::from_str(&json).expect("разбирается");
            assert_eq!(back, request);
        }
    }

    #[test]
    fn mutating_requests_are_distinguished() {
        // Журнал из запросов состояния состоял бы целиком из них.
        assert!(Request::Disconnect.is_mutating());
        assert!(Request::Connect { profile: None }.is_mutating());
        assert!(!Request::Status.is_mutating());
        assert!(!Request::Ping.is_mutating());
    }

    #[test]
    fn every_request_has_a_name() {
        for request in [
            Request::Ping,
            Request::Status,
            Request::Disconnect,
            Request::Subscribe,
        ] {
            assert!(!request.name().is_empty());
        }
    }

    #[test]
    fn config_travels_whole() {
        // Частичное обновление означало бы, что демон и интерфейс держат
        // разные представления о настройках и однажды разойдутся.
        let request = Request::SetConfig {
            config: Box::new(RootConfig::default()),
        };
        let json = serde_json::to_string(&request).expect("сериализуется");
        let back: Request = serde_json::from_str(&json).expect("разбирается");
        assert!(matches!(back, Request::SetConfig { .. }));
    }
}
