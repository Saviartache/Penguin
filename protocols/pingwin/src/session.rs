//! Соединение с сервером по QUIC: HTTP/3, опознание (один раз на соединение).

use std::time::Duration;

use penguin_core::address::SocketAddress;
use penguin_proto::dialer::Dialer;
use penguin_transport::deadline;
use penguin_transport::h3::{self, Request};
use penguin_transport::quic::{self, QuicLink};
use penguin_transport::tls::ALPN_H3;

use crate::connection::Target;
use crate::datagram::PingwinDatagram;
use crate::error::{PingwinError, PingwinResult};
use crate::stream::PingwinStream;
use crate::wire::auth::{self, ClientAuth};
use crate::wire::keys::{EXPORTER_LABEL, KEY_LEN};
use crate::wire::udp;

/// Опознанное соединение HTTP/3.
pub(crate) struct Session {
    link: QuicLink,
    h3: h3::Connection,
    authority: String,
}

impl Session {
    /// Поднимает QUIC и HTTP/3 и проходит опознание.
    pub(crate) async fn establish(target: &Target, dialer: &dyn Dialer) -> PingwinResult<Self> {
        let link = quic::connect(
            dialer,
            &target.host,
            target.port,
            &target.server_name,
            &target.tls,
            &[ALPN_H3],
        )
        .await?;
        let session = Self {
            h3: h3::Connection::new(link.connection.clone(), h3::Options { datagrams: true })
                .await?,
            link,
            authority: target.server_name.clone(),
        };
        if let Err(err) =
            deadline::handshake("опознание pingwin", session.authenticate(target)).await
        {
            session.close().await;
            return Err(err);
        }
        Ok(session)
    }

    async fn authenticate(&self, target: &Target) -> PingwinResult<()> {
        let mut exporter = [0u8; KEY_LEN];
        self.link
            .connection
            .export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
            .map_err(|_| PingwinError::malformed("экспорт ключей TLS не удался"))?;
        let auth = ClientAuth::new(&exporter, &target.server_public, &target.password)?;

        let request =
            Request::new("GET", &self.authority, auth::PATH).header("authorization", &auth.header);
        let mut stream = self.h3.send_request(&request).await?;
        stream.finish()?;
        let response = stream.response().await?;
        if !auth.accepts(response.status(), response.header(auth::PROOF_HEADER)) {
            return Err(PingwinError::Rejected);
        }
        Ok(())
    }

    /// Соединение живо.
    pub(crate) fn is_alive(&self) -> bool {
        self.link.connection.close_reason().is_none()
    }

    /// Открывает поток до `target`, не дожидаясь ответа сервера.
    pub(crate) async fn open_tcp(&self, target: &SocketAddress) -> PingwinResult<PingwinStream> {
        let authority = target.to_wire();
        let stream = self.h3.send_request(&Request::connect(&authority)).await?;
        Ok(PingwinStream::h3(stream, authority))
    }

    /// Открывает датаграммный канал; ждёт согласия сервера.
    pub(crate) async fn open_udp(&self) -> PingwinResult<PingwinDatagram> {
        let request = Request::extended_connect(udp::PROTOCOL, &self.authority, udp::PATH);
        let mut stream = self.h3.send_request(&request).await?;
        let status = stream.response().await?.status();
        if status != 200 {
            return Err(PingwinError::malformed(format!(
                "сервер не открыл датаграммный канал: ответ {status}"
            )));
        }
        let incoming = self.h3.register_datagrams(stream.id())?;
        Ok(PingwinDatagram::new(self.h3.clone(), stream, incoming))
    }

    /// Оборот по оценке QUIC.
    pub(crate) fn rtt(&self) -> Duration {
        self.link.connection.rtt()
    }

    /// Закрывает соединение штатно.
    pub(crate) async fn close(&self) {
        self.link.close(h3::code::H3_NO_ERROR, b"").await;
    }
}
