//! Серверная сторона: приём соединений и диспетчеризация.
//!
//! Соединение — «запрос, ответ» либо, после [`Request::Subscribe`], только
//! события; на проводе они неразличимы, режимы смешивать нельзя.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::auth;
use crate::codec;
use crate::error::IpcResult;
use crate::schema::{Event, Request, Response};
use crate::transport::{self, Listener, Stream};

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
    pub async fn serve(&self, cancel: CancellationToken) -> IpcResult<()> {
        let listener = transport::listen()?;
        self.serve_with_listener(listener, cancel).await
    }

    /// Обслуживает уже занятый канал до отмены.
    ///
    /// Занимать его ([`transport::listen`]) надо до восстановления сети: второй
    /// демон не должен успеть тронуть её, не узнав о первом.
    pub async fn serve_with_listener(
        &self,
        mut listener: Listener,
        cancel: CancellationToken,
    ) -> IpcResult<()> {
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
                    // Выходить нельзя: демон перестал бы отвечать насовсем.
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
    mut stream: Stream,
    handler: Arc<dyn Handler>,
    cancel: CancellationToken,
) -> IpcResult<()> {
    auth::check_peer(&stream)?;

    loop {
        let request: Request = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            // Ошибка чтения — клиент закрыл соединение.
            request = codec::read(&mut stream) => match request {
                Ok(request) => request,
                Err(_) => break,
            },
        };

        if request.is_mutating() {
            tracing::info!(request = request.name(), "запрос из канала управления");
        }

        if matches!(request, Request::Subscribe) {
            codec::write(&mut stream, &Response::Ok).await?;
            return stream_events(&mut stream, handler.subscribe(), cancel).await;
        }

        let response = handler.handle(request).await;
        codec::write(&mut stream, &response).await?;
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
            // Пропуск событий не повод рвать соединение.
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
    async fn a_prebound_listener_serves_requests_and_cancels() {
        // Свой канал, не служебный.
        let label = format!("penguin-prebound-test-{}", std::process::id());
        #[cfg(unix)]
        let (listener, path) = {
            let path = std::env::temp_dir().join(&label).join("control.sock");
            (transport::listen_at(&path).unwrap(), path)
        };
        #[cfg(windows)]
        let listener = transport::windows::Listener::bind(&label).unwrap();
        let (handler, _events) = handler();
        let server = Server::new(handler);
        let cancel = CancellationToken::new();
        let serving = server.serve_with_listener(listener, cancel.clone());
        let client = async {
            #[cfg(unix)]
            let mut stream = transport::connect_at(&path).await.unwrap();
            #[cfg(windows)]
            let mut stream = transport::windows::connect_to(&label).await.unwrap();
            codec::write(&mut stream, &Request::Ping).await.unwrap();
            assert!(matches!(
                codec::read::<_, Response>(&mut stream).await.unwrap(),
                Response::Pong { .. }
            ));
            cancel.cancel();
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (result, ()) = tokio::join!(serving, client);
            result.unwrap();
        })
        .await
        .expect("prebound server responded and stopped");
        #[cfg(unix)]
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }

    #[tokio::test]
    async fn handler_answers_a_ping() {
        let (handler, _events) = handler();
        assert!(matches!(
            handler.handle(Request::Ping).await,
            Response::Pong { .. }
        ));
        assert!(handler.handle(Request::Status).await.is_error());
    }

    #[tokio::test]
    async fn lagging_subscriber_does_not_break_the_stream() {
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

        stream_events(&mut sink, receiver, cancel)
            .await
            .expect("поток завершился штатно");
    }
}
