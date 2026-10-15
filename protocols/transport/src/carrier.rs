//! Чем поток протокола переносится до сервера — общее для Trojan, VLESS и
//! VMess: значения те же, что `network` у Xray.
//!
//! - `tcp` — голый поток внутри TLS (или REALITY).
//! - `grpc` — вызов gRPC `Tun` по HTTP/2 поверх того же TLS.
//! - `xhttp` — XHTTP `stream-one` по HTTP/3; TLS у него свой, в QUIC.
//!
//! HTTP/1.1 нет ни в одном: WebSocket и `httpupgrade` убраны.

use serde::{Deserialize, Serialize};

use crate::tls::{ALPN_H2, ALPN_H3, ALPN_HTTP11};

/// Перенос потока.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Carrier {
    /// Голый поток.
    #[default]
    Tcp,
    /// gRPC по HTTP/2.
    Grpc,
    /// XHTTP по HTTP/3.
    Xhttp,
}

impl Carrier {
    /// Нужны ли путь (у gRPC — `serviceName`) и `Host`.
    pub fn uses_path(self) -> bool {
        !matches!(self, Self::Tcp)
    }

    /// Идёт ли перенос по QUIC, а не поверх соединения TCP.
    pub fn is_quic(self) -> bool {
        matches!(self, Self::Xhttp)
    }

    /// Что объявлять в ALPN, если человек не задал своё.
    ///
    /// У голого потока — то же, что у браузера на обычном сайте: сервер
    /// обязан выглядеть этим сайтом. Это объявление в TLS, а не разговор
    /// по HTTP/1.1. У gRPC — `h2`, иначе сервер не поймёт HTTP/2; у XHTTP —
    /// `h3`.
    pub fn default_alpn(self) -> &'static [&'static [u8]] {
        match self {
            Self::Tcp => &[ALPN_H2, ALPN_HTTP11],
            Self::Grpc => &[ALPN_H2],
            Self::Xhttp => &[ALPN_H3],
        }
    }
}

/// Надевает перенос на уже открытое соединение (TLS, REALITY или TCP).
///
/// XHTTP так не умеет — у него своё соединение QUIC, и вызывать это для него
/// — ошибка вызывающего, она возвращается как ошибка настроек.
#[cfg(feature = "h2")]
pub async fn wrap<S>(
    secure: S,
    carrier: Carrier,
    authority: &str,
    path: &str,
) -> crate::TransportResult<Box<dyn penguin_proto::stream::ProxyStream>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    match carrier {
        Carrier::Tcp => Ok(Box::new(secure)),
        Carrier::Grpc => Ok(Box::new(
            crate::grpc::connect(secure, authority, path).await?,
        )),
        Carrier::Xhttp => Err(crate::TransportError::config(
            "XHTTP идёт по своему соединению QUIC, а не поверх TCP",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_xray() {
        for (carrier, name) in [
            (Carrier::Tcp, "\"tcp\""),
            (Carrier::Grpc, "\"grpc\""),
            (Carrier::Xhttp, "\"xhttp\""),
        ] {
            assert_eq!(serde_json::to_string(&carrier).expect("пишется"), name);
        }
        assert!(serde_json::from_str::<Carrier>("\"ws\"").is_err());
    }

    #[test]
    fn grpc_speaks_h2_and_xhttp_speaks_h3() {
        assert_eq!(Carrier::Grpc.default_alpn(), &[ALPN_H2]);
        assert_eq!(Carrier::Xhttp.default_alpn(), &[ALPN_H3]);
        assert!(Carrier::Xhttp.is_quic());
        assert!(!Carrier::Tcp.uses_path());
    }
}
