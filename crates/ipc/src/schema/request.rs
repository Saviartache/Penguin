//! Запросы: подключиться, отключиться, править правила, перечислить процессы.
//!
//! Список запросов — это всё, что может сделать любой, кто дотянулся до канала.

use penguin_config::RootConfig;
use penguin_core::id::ProfileId;
use serde::{Deserialize, Serialize};

/// Что просят сделать.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "request")]
pub enum Request {
    /// Проверка связи: по ответу видна версия демона.
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

    /// Заменить настройки целиком.
    SetConfig {
        /// Новые настройки.
        config: Box<RootConfig>,
    },

    /// Объяснить, что случится с таким соединением, не открывая его.
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

    /// Подписаться на события; соединение становится потоком событий.
    Subscribe,

    /// Опустить тоннель и выйти (в отличие от [`Self::Disconnect`]); служба останавливает себя сама.
    Shutdown,

    /// Кусок базы GeoIP: служба не читает каталог пользователя, куда её качает окно.
    /// Куски идут по порядку; последний заменяет базу службы целиком.
    PutGeoIp {
        /// С какого байта кусок; `0` начинает передачу заново.
        offset: u64,
        /// Размер всей базы.
        total: u64,
        /// Байты куска, не длиннее [`GEOIP_CHUNK`].
        #[serde(with = "super::hex")]
        data: Vec<u8>,
    },
}

/// Наибольший кусок базы GeoIP: в hex он вдвое длиннее и обязан влезть в
/// [`crate::codec::MAX_MESSAGE`].
pub const GEOIP_CHUNK: usize = 256 * 1024;

impl Request {
    /// Меняет ли запрос состояние системы; только такие пишутся в журнал.
    pub fn is_mutating(&self) -> bool {
        matches!(
            self,
            Self::Connect { .. } | Self::Disconnect | Self::SetConfig { .. } | Self::Shutdown
        )
    }

    /// Ждёт ли ответ работы, а не памяти (замер задержки, обход процессов); от него зависит срок ожидания.
    pub fn does_work(&self) -> bool {
        matches!(
            self,
            Self::Connect { .. }
                | Self::Disconnect
                | Self::SetConfig { .. }
                | Self::Shutdown
                | Self::Probe { .. }
                | Self::ListProcesses
                | Self::PutGeoIp { .. }
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
            Self::Shutdown => "shutdown",
            Self::PutGeoIp { .. } => "put_geoip",
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
            Request::Shutdown,
        ];

        for request in requests {
            let json = serde_json::to_string(&request).expect("сериализуется");
            let back: Request = serde_json::from_str(&json).expect("разбирается");
            assert_eq!(back, request);
        }
    }

    #[test]
    fn mutating_requests_are_distinguished() {
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
    fn the_largest_geoip_chunk_fits_one_message() {
        let request = Request::PutGeoIp {
            offset: 0,
            total: GEOIP_CHUNK as u64,
            data: vec![0xff; GEOIP_CHUNK],
        };
        let json = serde_json::to_vec(&request).expect("сериализуется");
        assert!(json.len() <= crate::codec::MAX_MESSAGE);
        let back: Request = serde_json::from_slice(&json).expect("разбирается");
        assert_eq!(back, request);
    }

    #[test]
    fn config_travels_whole() {
        let request = Request::SetConfig {
            config: Box::new(RootConfig::default()),
        };
        let json = serde_json::to_string(&request).expect("сериализуется");
        let back: Request = serde_json::from_str(&json).expect("разбирается");
        assert!(matches!(back, Request::SetConfig { .. }));
    }
}
