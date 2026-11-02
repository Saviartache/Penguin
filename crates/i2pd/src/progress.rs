//! Ход запуска i2pd по его журналу: откуда качаются узлы и сколько пришло.

/// Шаг запуска, понятный человеку.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// i2pd запущен, ждём HTTP-прокси.
    Starting,
    /// Качаются узлы сети (reseed) с этого узла.
    Downloading(String),
    /// Узлы не скачались.
    DownloadFailed,
    /// HTTP-прокси открыт; узлов в базе столько.
    Ready(usize),
}

impl Progress {
    /// Текст для окна.
    pub fn message(&self) -> String {
        match self {
            Self::Starting => "I2P: запуск i2pd".to_owned(),
            Self::Downloading(host) => format!("I2P: загрузка узлов сети с {host}"),
            Self::DownloadFailed => "I2P: узлы сети не скачались — повтор".to_owned(),
            Self::Ready(0) => "I2P: узлы уже есть, строятся туннели".to_owned(),
            Self::Ready(routers) => {
                format!("I2P: получено узлов — {routers}, строятся туннели")
            }
        }
    }

    /// Плохая ли это новость.
    pub fn is_warning(&self) -> bool {
        matches!(self, Self::DownloadFailed)
    }
}

/// Что строка журнала i2pd значит для запуска.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Line {
    /// Шаг, который стоит показать.
    Step(Progress),
    /// В базу добавлен узел.
    Router,
}

/// Разбирает строку `ЧЧ:ММ:СС@поток/уровень - Модуль: текст`.
pub(crate) fn parse(line: &str) -> Option<Line> {
    let (_, text) = line.split_once(" - ")?;
    if let Some(url) = text.strip_prefix("Reseed: Downloading SU3 from ") {
        return Some(Line::Step(Progress::Downloading(host_of(url).to_owned())));
    }
    if text.starts_with("Reseed: SU3 download failed")
        || text.starts_with("Reseed: Failed to reseed")
    {
        return Some(Line::Step(Progress::DownloadFailed));
    }
    text.starts_with("NetDb: RouterInfo added")
        .then_some(Line::Router)
}

/// Узел из `https://узел/путь`.
fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split(['/', '?']).next().unwrap_or(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Строки журнала i2pd 3.0.0 (`loglevel = info`), записанные при запуске.
    #[test]
    fn recorded_lines_are_understood() {
        assert_eq!(
            parse(
                "20:45:12@856/info - Reseed: Downloading SU3 from https://github.com/Saviartache/penguin/releases/download/i2p-reseed/i2pseeds.su3"
            ),
            Some(Line::Step(Progress::Downloading("github.com".to_owned())))
        );
        assert_eq!(
            parse("20:45:12@856/warn - Reseed: SU3 download failed"),
            Some(Line::Step(Progress::DownloadFailed))
        );
        assert_eq!(
            parse(
                "22:03:03@856/info - NetDb: RouterInfo added: YoPCaYlg6R~yLRBBuHeDzNZ1udvDFo6nAZGKeSzGCNQ="
            ),
            Some(Line::Router)
        );
        assert_eq!(
            parse("22:03:06@170/info - Tunnel: Outbound tunnel 3093242772 has been created"),
            None
        );
        assert_eq!(parse("мусор"), None);
    }

    #[test]
    fn only_a_failure_is_a_warning() {
        assert!(Progress::DownloadFailed.is_warning());
        assert!(!Progress::Ready(75).is_warning());
        assert!(Progress::Ready(75).message().contains("75"));
    }
}
