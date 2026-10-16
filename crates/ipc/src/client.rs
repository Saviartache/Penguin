//! Клиентская сторона: запрос-ответ и подписка на события.
//!
//! [`Client::subscribe`] необратимо превращает соединение в поток событий;
//! для команд нужно отдельное соединение.

use crate::codec;
use crate::error::{IpcError, IpcResult};
use crate::schema::{Event, Request, Response};
use crate::transport::{self, Stream};

/// Соединение с демоном.
pub struct Client {
    stream: Stream,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl Client {
    /// Подключается к демону; на Unix допускает запасной канал пользователя.
    ///
    /// GUI и управление службой используют [`Self::connect_service`].
    pub async fn connect() -> IpcResult<Self> {
        Ok(Self {
            stream: transport::connect().await?,
        })
    }

    /// Подключается только к системной службе, без запасного канала, даже под root.
    pub async fn connect_service() -> IpcResult<Self> {
        Ok(Self {
            stream: transport::connect_service().await?,
        })
    }

    /// Отправляет запрос и ждёт ответ.
    pub async fn request(&mut self, request: Request) -> IpcResult<Response> {
        codec::write(&mut self.stream, &request).await?;
        codec::read(&mut self.stream).await
    }

    /// Проверяет, что демон жив, и возвращает его версию.
    pub async fn ping(&mut self) -> IpcResult<String> {
        Ok(self.hello().await?.0)
    }

    /// Версия демона и отпечаток его сборки: по нему видно, что служба работает прежним файлом.
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

    /// Превращает соединение в поток событий; необратимо.
    pub async fn subscribe(mut self) -> IpcResult<EventStream> {
        match self.request(Request::Subscribe).await? {
            Response::Ok => Ok(EventStream {
                stream: self.stream,
            }),
            other => Err(unexpected(&other)),
        }
    }
}

/// Сколько ждать ответа службы: окно ждёт столько при каждом открытии, до запроса прав.
pub const ANSWER_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1500);

/// Отпечаток сборки работающего демона; `None` — не отвечает.
///
/// Допускает запасной канал, как [`Client::connect`]; для GUI и готовности службы —
/// [`greet_service`]. Одного соединения мало: зависший демон его принимает и молчит.
pub async fn greet() -> Option<String> {
    greet_with(Client::connect()).await
}

/// Отпечаток сборки системной службы; `None` — не отвечает за [`ANSWER_TIMEOUT`].
///
/// Только [`Client::connect_service`], без запасного канала.
pub async fn greet_service() -> Option<String> {
    greet_with(Client::connect_service()).await
}

async fn greet_with(
    connect: impl std::future::Future<Output = IpcResult<Client>>,
) -> Option<String> {
    let greeting = tokio::time::timeout(ANSWER_TIMEOUT, async {
        let mut client = connect.await.ok()?;
        let (_, build) = client.hello().await.ok()?;
        Some(build)
    })
    .await;

    greeting.ok().flatten()
}

/// Отвечает ли демон, с запасным каналом [`greet`].
pub async fn answers() -> bool {
    greet().await.is_some()
}

/// Отвечает ли системная служба; для проверки готовности.
pub async fn answers_service() -> bool {
    greet_service().await.is_some()
}

/// Поток событий от демона.
pub struct EventStream {
    stream: Stream,
}

impl std::fmt::Debug for EventStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventStream").finish_non_exhaustive()
    }
}

impl EventStream {
    /// Ждёт следующее событие; ошибка — демон отключился.
    pub async fn next(&mut self) -> IpcResult<Event> {
        codec::read(&mut self.stream).await
    }
}

/// Демон ответил не тем: обычно служба осталась старой после обновления окна.
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
        let err = unexpected(&Response::error("неверный пароль", true));
        assert!(err.to_string().contains("неверный пароль"));
    }

    #[test]
    fn other_responses_are_shown_as_json() {
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
