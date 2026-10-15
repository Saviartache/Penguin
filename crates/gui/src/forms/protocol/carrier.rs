//! Перенос потока у Trojan, VLESS и VMess: значения поля и разбор ссылок.

use crate::forms::link::Link;

/// Чем поток переносится. Первое — умолчание нового профиля: голый поток и
/// есть настоящий протокол, остальные нужны, когда по дороге стоит CDN.
pub const TRANSPORTS: &[&str] = &["tcp", "grpc", "xhttp"];

/// Значение поля по имени переноса из ссылки (`type` или `net`).
///
/// `raw` — новое имя `tcp` у Xray, `splithttp` — старое `xhttp`. WebSocket и
/// `httpupgrade` — это HTTP/1.1, и клиент их не говорит: такая ссылка —
/// понятная ошибка, а не профиль, который молча не соединится.
pub fn transport(raw: &str) -> Result<&'static str, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "tcp" | "raw" => Ok("tcp"),
        "grpc" => Ok("grpc"),
        "xhttp" | "splithttp" => Ok("xhttp"),
        _ => Err(crate::i18n::s().link_unsupported_transport.to_owned()),
    }
}

/// Перенос из ссылки Xray: `type`, затем `path` (у gRPC — `serviceName`) и
/// `host`. У голого потока путь и `host` не пишутся: настройки их отвергнут.
pub fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let mut values = Vec::new();
    let Some(raw) = link.query.get("type") else {
        return Ok(values);
    };
    let transport = transport(&raw)?;
    values.push(("transport", transport.to_owned()));
    if transport == "tcp" {
        return Ok(values);
    }
    let path = match transport {
        "grpc" => link.query.get("serviceName"),
        _ => link.query.get("path"),
    };
    values.extend(path.map(|path| ("path", path)));
    values.extend(link.query.get("host").map(|host| ("host", host)));
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_names_map_to_the_three_carriers() {
        assert_eq!(transport("raw"), Ok("tcp"));
        assert_eq!(transport("GRPC"), Ok("grpc"));
        assert_eq!(transport("splithttp"), Ok("xhttp"));
        assert!(transport("ws").is_err());
        assert!(transport("httpupgrade").is_err());
    }
}
