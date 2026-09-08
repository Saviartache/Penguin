//! Устанавливает транспорт `CONNECT-IP`: TCP через `Dialer`, TLS, апгрейд.
//!
//! Ни `quinn`, ни `h3` здесь нет вовсе — почему, см. [`crate::ip`].

use penguin_core::address::SocketAddress;
use penguin_proto::connect;
use penguin_proto::dialer::Dialer;
use penguin_proto::stream::ProxyStream;
use penguin_transport::deadline;
use penguin_transport::tls::{ALPN_HTTP11, TlsClient};
use penguin_transport::ws::handshake::read_head;
use tokio::io::AsyncWriteExt;

use super::request;
use crate::config::MasqueConfig;
use crate::error::{MasqueError, MasqueResult};

/// Дозванивается до прокси и проводит апгрейд до потока капсул `CONNECT-IP`.
///
/// Возвращает поток и хвост, пришедший вместе с ответом на апгрейд: сервер
/// вправе прислать первую капсулу тем же пакетом, что и заголовки ответа, и
/// потерять её значило бы потерять начало согласования адреса.
pub(super) async fn open(
    dialer: &dyn Dialer,
    config: &MasqueConfig,
) -> MasqueResult<(Box<dyn ProxyStream>, Vec<u8>)> {
    config.validate()?;
    let (host, port) = config.endpoint()?;
    let tls = TlsClient::new(&config.tls, &host, &[ALPN_HTTP11])?;

    deadline::handshake("CONNECT-IP", async {
        let plain = connect::dial(dialer, &host, port)
            .await
            .map_err(|e| MasqueError::Disconnected(e.to_string()))?;
        let mut secure = tls.connect(plain).await?;

        // `host` больше не нужен по ссылке — последнее использование
        // забирает его целиком в заголовок `Host`.
        let host_header = SocketAddress::new(host, port).to_wire();
        let text = request::request_text(&host_header, config.authorization.as_deref());
        secure.write_all(text.as_bytes()).await?;
        secure.flush().await?;

        let (head, tail) = read_head(&mut secure).await?;
        request::check_response(&head)?;

        Ok((Box::new(secure) as Box<dyn ProxyStream>, tail))
    })
    .await
}
