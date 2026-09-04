//! Клиентская сторона: запрос-ответ и подписка на события.
//!
//! Соединение живёт в одном из двух режимов, и переключение необратимо:
//! [`Client::subscribe`] превращает соединение в поток событий, после чего
//! запросы по нему больше не отправляются. Для команд нужно отдельное
//! соединение — открыть его дёшево, а перепутать режимы стоило бы дороже
//! любой экономии.

use interprocess::local_socket::tokio::prelude::*;
use tokio::io::{ReadHalf, WriteHalf};

use crate::codec;
use crate::error::{IpcError, IpcResult};
use crate::schema::{Event, Request, Response};
use crate::transport;

/// Соединение с демоном.
pub struct Client {
    reader: ReadHalf<LocalSocketStream>,
    writer: WriteHalf<LocalSocketStream>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl Client {
    /// Подключается к демону.
    pub async fn connect() -> IpcResult<Self> {
        let stream = transport::connect().await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self { reader, writer })
    }

    /// Отправляет запрос и ждёт ответ.
    pub async fn request(&mut self, request: Request) -> IpcResult<Response> {
        codec::write(&mut self.writer, &request).await?;
        codec::read(&mut self.reader).await
    }

    /// Проверяет, что демон жив, и возвращает его версию.
    pub async fn ping(&mut self) -> IpcResult<String> {
        Ok(self.hello().await?.0)
    }

    /// Версия демона и отпечаток его сборки.
    ///
    /// Отпечаток нужен окну: по нему видно, что служба работает прежним
    /// файлом, — а значит, положенное рядом исправление ещё не действует.
    pub async fn hello(&mut self) -> IpcResult<(String, String)> {
        match self.request(Request::Ping).await? {
            Response::Pong { version, build } => Ok((version, build)),
            other => Err(unexpected(&other)),
        }
    }

    /// Состояние клиента.
    pub async fn status(&mut self) -> IpcResult<crate::schema::StatusReport> {
        match self.request(Request::Status).await? {
            Response::Status(status) => Ok(*status),
            other => Err(unexpected(&other)),
        }
    }

    /// Настройки.
    pub async fn config(&mut self) -> IpcResult<penguin_config::RootConfig> {
        match self.request(Request::GetConfig).await? {
            Response::Config(config) => Ok(*config),
            other => Err(unexpected(&other)),
        }
    }

    /// Превращает соединение в поток событий.
    ///
    /// Необратимо: запросы по нему больше не отправляются. Для команд нужно
    /// открыть отдельное соединение.
    pub async fn subscribe(mut self) -> IpcResult<EventStream> {
        match self.request(Request::Subscribe).await? {
            Response::Ok => Ok(EventStream {
                reader: self.reader,
            }),
            other => Err(unexpected(&other)),
        }
    }
}

/// Сколько ждать, пока служба отзовётся.
///
/// Приветствие — самый дешёвый запрос: демон отвечает на него из памяти, не
/// трогая ни тоннеля, ни настроек, и канал у них общий на одной машине. Ответ
/// на него приходит за микросекунды; полторы секунды здесь — не срок ожидания,
/// а признание того, что отвечать некому.
///
/// Щедрее нельзя: этот срок окно ждёт при каждом открытии, прежде чем спросить
/// права, и каждая лишняя секунда — это секунда неподвижного окна перед
/// запросом пароля.
pub const ANSWER_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1500);

/// Отпечаток сборки работающей службы. `None` — служба не отвечает.
///
/// Открытого соединения для этого вопроса мало, и это не осторожность, а
/// опыт: демон, зависший с поднятым тоннелем, соединение всё равно принимает —
/// его дослушивает ядро, — и молчит. Тот, кто счёл такое соединение ответом,
/// встаёт на первом же запросе навсегда: окно не открывается, а человек видит
/// «Запускаю службу» и больше ничего.
pub async fn greet() -> Option<String> {
    let greeting = tokio::time::timeout(ANSWER_TIMEOUT, async {
        let mut client = Client::connect().await.ok()?;
        let (_, build) = client.hello().await.ok()?;
        Some(build)
    })
    .await;

    greeting.ok().flatten()
}

/// Отвечает ли служба.
pub async fn answers() -> bool {
    greet().await.is_some()
}

/// Поток событий от демона.
pub struct EventStream {
    reader: ReadHalf<LocalSocketStream>,
}

impl std::fmt::Debug for EventStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventStream").finish_non_exhaustive()
    }
}

impl EventStream {
    /// Ждёт следующее событие.
    ///
    /// Ошибка означает, что демон отключился, — интерфейс на это отвечает
    /// переподключением, а не падением.
    pub async fn next(&mut self) -> IpcResult<Event> {
        codec::read(&mut self.reader).await
    }
}

/// Демон ответил не тем.
///
/// Почти всегда означает разные версии по разные стороны канала: служба
/// осталась старой после обновления интерфейса.
fn unexpected(response: &Response) -> IpcError {
    match response {
        Response::Error { message, .. } => IpcError::UnexpectedResponse(message.clone()),
        other => IpcError::UnexpectedResponse(
            serde_json::to_string(other).unwrap_or_else(|_| "?".to_owned()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_response_keeps_the_message() {
        // Пользователь должен увидеть, что именно ответил демон, а не
        // «неожиданный ответ».
        let err = unexpected(&Response::error("неверный пароль", true));
        assert!(err.to_string().contains("неверный пароль"));
    }

    #[test]
    fn other_responses_are_shown_as_json() {
        // Расхождение версий видно по содержимому ответа — его и печатаем.
        let err = unexpected(&Response::Ok);
        assert!(err.to_string().contains("ok"));
    }

    #[tokio::test]
    async fn connecting_without_a_daemon_says_so() {
        match Client::connect().await {
            Ok(_) => {}
            Err(err) => assert!(
                matches!(err, IpcError::DaemonNotRunning | IpcError::AccessDenied),
                "невнятная ошибка: {err}"
            ),
        }
    }
}
