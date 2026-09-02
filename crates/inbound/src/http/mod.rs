//! Локальный HTTP-прокси.
//!
//! Существует ради приложений, которые умеют только его: системные настройки
//! прокси в Windows, корпоративные утилиты, старые сборки. Поддерживается один
//! метод — `CONNECT`; почему только он, объяснено в [`connect`].

pub mod connect;

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::network::Network;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::error::InboundResult;
use crate::inbound::{Inbound, InboundHandler, InboundRequest};

/// Локальный HTTP-прокси.
pub struct HttpInbound {
    listener: TcpListener,
    handler: Arc<dyn InboundHandler>,
}

impl HttpInbound {
    /// Занимает адрес.
    pub async fn bind(listen: SocketAddr, handler: Arc<dyn InboundHandler>) -> InboundResult<Self> {
        let listener = TcpListener::bind(listen).await?;
        tracing::info!(addr = %listener.local_addr()?, "HTTP-прокси слушает");
        Ok(Self { listener, handler })
    }
}

#[async_trait]
impl Inbound for HttpInbound {
    fn name(&self) -> &'static str {
        "http"
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.listener.local_addr().ok()
    }

    async fn serve(self: Box<Self>, cancel: CancellationToken) {
        loop {
            let accepted = tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                accepted = self.listener.accept() => accepted,
            };

            let Ok((stream, source)) = accepted else {
                continue;
            };
            let handler = Arc::clone(&self.handler);

            tokio::spawn(async move {
                if let Err(err) = serve_connection(stream, source, handler).await {
                    tracing::debug!(%source, %err, "соединение HTTP завершилось с ошибкой");
                }
            });
        }

        tracing::info!("HTTP-прокси остановлен");
    }
}

async fn serve_connection(
    stream: TcpStream,
    source: SocketAddr,
    handler: Arc<dyn InboundHandler>,
) -> InboundResult<()> {
    let _ = stream.set_nodelay(true);
    let mut reader = BufReader::new(stream);

    let target = match connect::read_request(&mut reader).await {
        Ok(target) => target,
        Err(err) => {
            let mut stream = reader.into_inner();
            let _ = connect::reply_failure(&mut stream, 400, "Bad Request").await;
            return Err(err);
        }
    };

    let request = InboundRequest {
        source,
        target: target.clone(),
        network: Network::Tcp,
    };

    let outbound = match handler.open_tcp(&request).await {
        Ok(outbound) => outbound,
        Err(err) => {
            tracing::debug!(%target, %err, "не удалось открыть соединение");
            let mut stream = reader.into_inner();
            let _ = connect::reply_failure(&mut stream, 502, "Bad Gateway").await;
            return Ok(());
        }
    };

    let mut stream = reader.into_inner();
    connect::reply_established(&mut stream).await?;

    let (mut client_read, mut client_write) = stream.into_split();
    let (mut remote_read, mut remote_write) = tokio::io::split(outbound);

    let (up, down) = tokio::join!(
        async {
            let result = tokio::io::copy(&mut client_read, &mut remote_write).await;
            let _ = remote_write.shutdown().await;
            result
        },
        async {
            let result = tokio::io::copy(&mut remote_read, &mut client_write).await;
            let _ = client_write.shutdown().await;
            result
        }
    );

    tracing::debug!(
        %target,
        uploaded = up.unwrap_or(0),
        downloaded = down.unwrap_or(0),
        "соединение закрыто"
    );
    Ok(())
}
