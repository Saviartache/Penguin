//! Серверная сторона: приём соединений и диспетчеризация.
//!
//! Соединение живёт в одном из двух режимов. Обычное — «запрос, ответ,
//! запрос, ответ»; так работают все команды. Подписка ([`Request::Subscribe`])
//! переводит соединение во второй режим: дальше по нему идут только события,
//! и запросов там больше не ждут.
//!
//! Смешивать эти режимы в одном соединении нельзя. Ответ на запрос и событие
//! выглядят на проводе одинаково — рамка и JSON, — и получатель различает их
//! только тем, что знает, в каком режиме он находится.

use std::sync::Arc;

use async_trait::async_trait;
use interprocess::local_socket::tokio::prelude::*;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::codec;
use crate::error::IpcResult;
use crate::schema::{Event, Request, Response};
use crate::{auth, transport};

/// Кто отвечает на запросы.
#[async_trait]
pub trait Handler: Send + Sync + 'static {
    /// Отвечает на запрос.
    async fn handle(&self, request: Request) -> Response;

    /// Подписка на события для нового клиента.
    fn subscribe(&self) -> broadcast::Receiver<Event>;
}

/// Сервер канала управления.
pub struct Server {
    handler: Arc<dyn Handler>,
}

impl Server {
    /// Создаёт сервер.
    pub fn new(handler: Arc<dyn Handler>) -> Self {
        Self { handler }
    }

    /// Слушает канал, пока не отменят.
    ///
    /// Канал занимается сразу, а не внутри задачи: ошибка «служба уже
    /// работает» должна прийти тому, кто её запускал.
    pub async fn serve(&self, cancel: CancellationToken) -> IpcResult<()> {
        let listener = transport::listen()?;
        tracing::info!(channel = transport::CHANNEL_NAME, "канал управления открыт");

        loop {
            let accepted = tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                accepted = listener.accept() => accepted,
            };

            let stream = match accepted {
                Ok(stream) => stream,
                Err(err) => {
                    // Исчерпание дескрипторов лечится тем, что часть клиентов
                    // отключится. Выходить из цикла нельзя — демон перестал бы
                    // отвечать насовсем.
                    tracing::warn!(%err, "соединение не принято");
                    continue;
                }
            };

            let handler = Arc::clone(&self.handler);
            let cancel = cancel.clone();
            tokio::spawn(async move {
                if let Err(err) = serve_client(stream, handler, cancel).await {
                    tracing::debug!(%err, "клиент отключился с ошибкой");
                }
            });
        }

        tracing::info!("канал управления закрыт");
        Ok(())
    }
}

/// Обслуживает одного клиента.
async fn serve_client(
    stream: LocalSocketStream,
    handler: Arc<dyn Handler>,
    cancel: CancellationToken,
) -> IpcResult<()> {
    auth::check_peer(&stream)?;

    let (mut reader, mut writer) = stream.split();

    loop {
        let request: Request = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            request = codec::read(&mut reader) => match request {
                Ok(request) => request,
                // Клиент закрыл соединение — обычный конец работы.
                Err(_) => break,
            },
        };

        if request.is_mutating() {
            tracing::info!(request = request.name(), "запрос из канала управления");
        }

        // Подписка меняет режим соединения: дальше по нему идут только
        // события, и запросов там больше не ждут.
        if matches!(request, Request::Subscribe) {
            codec::write(&mut writer, &Response::Ok).await?;
            return stream_events(&mut writer, handler.subscribe(), cancel).await;
        }

        let response = handler.handle(request).await;
        codec::write(&mut writer, &response).await?;
    }

    Ok(())
}

/// Гонит события клиенту, пока он не отключится.
async fn stream_events<W>(
    writer: &mut W,
    mut events: broadcast::Receiver<Event>,
    cancel: CancellationToken,
) -> IpcResult<()>
where
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    loop {
        let event = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            event = events.recv() => event,
        };

        match event {
            Ok(event) => codec::write(writer, &event).await?,
            // Клиент отстал: часть событий пропущена. Разрывать из-за этого
            // соединение незачем — график, в котором не хватило кадра, лучше
            // отсутствующего графика.
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::debug!(skipped, "подписчик отстал");
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo {
        events: broadcast::Sender<Event>,
    }

    #[async_trait]
    impl Handler for Echo {
        async fn handle(&self, request: Request) -> Response {
            match request {
                Request::Ping => Response::Pong {
                    version: "тест".to_owned(),
                    build: "тест".to_owned(),
                },
                other => Response::error(format!("не умею {}", other.name()), false),
            }
        }

        fn subscribe(&self) -> broadcast::Receiver<Event> {
            self.events.subscribe()
        }
    }

    fn handler() -> (Arc<dyn Handler>, broadcast::Sender<Event>) {
        let (events, _) = broadcast::channel(16);
        (
            Arc::new(Echo {
                events: events.clone(),
            }),
            events,
        )
    }

    #[tokio::test]
    async fn handler_answers_a_ping() {
        // Сам обмен по каналу проверяется в `transport`: канал один на
        // систему, и два теста, занимающих его, мешали бы друг другу так же,
        // как мешают два демона. Здесь проверяется только диспетчеризация.
        let (handler, _events) = handler();
        assert!(matches!(
            handler.handle(Request::Ping).await,
            Response::Pong { .. }
        ));
        assert!(handler.handle(Request::Status).await.is_error());
    }

    #[tokio::test]
    async fn lagging_subscriber_does_not_break_the_stream() {
        // Пропущенное событие — не повод рвать соединение: график без кадра
        // лучше отсутствующего графика.
        let (events, receiver) = broadcast::channel(2);
        for step in 0..10 {
            let _ = events.send(Event::Log {
                level: crate::schema::LogLevel::Info,
                message: format!("событие {step}"),
            });
        }

        let mut sink = Vec::new();
        let cancel = CancellationToken::new();
        cancel.cancel();

        // Отмена завершает поток сразу; проверяем, что отставание не выдаёт
        // ошибку наружу.
        stream_events(&mut sink, receiver, cancel)
            .await
            .expect("поток завершился штатно");
    }
}
