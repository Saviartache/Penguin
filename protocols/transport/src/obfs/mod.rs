//! Простая обфускация: соединение, притворяющееся чем-то обычным.
//!
//! ```text
//!  http  первый запрос выглядит `GET /` с переходом на WebSocket
//!  tls   первая посылка выглядит приветствием TLS, дальше — записями данных
//! ```
//!
//! # Чего она не делает
//!
//! Не шифрует. Совсем. Внутри и так шифр протокола, а здесь только внешний
//! вид: тот, кто смотрит на поток, видит начало обычного разговора вместо
//! случайных байт с первого же пакета. Против того, кто читает весь поток и
//! сверяет его с настоящим HTTP, это не помогает и не задумано помогать.
//!
//! Способ старый — он пришёл из `simple-obfs`, плагина Shadowsocks, — и
//! известен всем, кто ищет. Заводится он здесь потому, что его требуют
//! серверы: у Snell обфускация задаётся на стороне сервера, и клиент обязан
//! говорить ровно так же, иначе разговора не выйдет.

pub mod http;
pub mod tls;

pub use http::HttpObfs;
pub use tls::TlsObfs;

/// Каким способом прикрыто соединение.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Mode {
    /// Никаким: байты протокола идут с первого же.
    #[default]
    None,
    /// Первый запрос выглядит обычным `GET` с переходом на WebSocket.
    Http,
    /// Первая посылка выглядит приветствием TLS.
    Tls,
}

impl Mode {
    /// Разбирает имя способа из настроек.
    ///
    /// Пустая строка — это «никакой», и так её пишут в настройках серверов.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim() {
            "" | "none" => Some(Self::None),
            "http" => Some(Self::Http),
            "tls" => Some(Self::Tls),
            _ => None,
        }
    }

    /// Имя способа в настройках.
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Http => "http",
            Self::Tls => "tls",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_name_survives_the_round_trip() {
        for mode in [Mode::None, Mode::Http, Mode::Tls] {
            assert_eq!(Mode::parse(mode.name()), Some(mode));
        }
    }

    #[test]
    fn an_empty_setting_means_no_obfuscation() {
        // Так её пишут в настройках серверов, и считать это ошибкой значит
        // отказать половине рабочих конфигураций.
        assert_eq!(Mode::parse(""), Some(Mode::None));
        assert_eq!(Mode::parse("  "), Some(Mode::None));
    }

    #[test]
    fn an_unknown_name_is_not_silently_the_default() {
        // Опечатка в имени способа даёт молчащее соединение, и сказать об
        // этом надо до подключения, а не после.
        assert_eq!(Mode::parse("htp"), None);
        assert_eq!(Mode::parse("websocket"), None);
    }
}
