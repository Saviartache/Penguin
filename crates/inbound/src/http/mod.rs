//! Локальный HTTP-прокси для приложений, умеющих только его. Поддерживается
//! один метод, `CONNECT` (см. [`connect`]).

pub mod connect;

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::network::Network;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::error::InboundResult;
use crate::inbound::{Inbound, InboundHandler, InboundRequest};
use crate::relay::relay;

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
    let mut reader = BufReader::with_capacity(1024, stream);

    let target = match connect::read_request(&mut reader).await {
        Ok(target) => target,
        Err(err) => {
            let _ = connect::reply_failure(reader.get_mut(), 400, "Bad Request").await;
            return Err(err);
        }
    };

    let request = InboundRequest {
        source,
        target,
        sniffed: None,
        network: Network::Tcp,
    };

    let mut outbound = match handler.open_tcp(&request).await {
        Ok(outbound) => outbound,
        Err(err) => {
            tracing::debug!(target = %request.target, %err, "не удалось открыть соединение");
            let _ = connect::reply_failure(reader.get_mut(), 502, "Bad Gateway").await;
            return Ok(());
        }
    };

    let mut stream = reader.into_inner();
    connect::reply_established(&mut stream).await?;

    relay(&mut stream, &mut outbound, &request.target).await;
    Ok(())
}
