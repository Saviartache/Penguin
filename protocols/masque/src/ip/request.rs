//! Запрос `CONNECT-IP` через HTTP/1.1 `Upgrade` (RFC 9484, §3, §4.2, §4.3).
//!
//! Почему через HTTP/1.1, а не расширенный CONNECT у HTTP/2/3, — в
//! документе [`crate::ip`].

use crate::error::{MasqueError, MasqueResult};

/// Путь по умолчанию: полный туннель, без ограничения на цель или протокол.
///
/// RFC 9484, §3 задаёт шаблон по умолчанию
/// `/.well-known/masque/ip/{target}/{ipproto}/`; §4.6 — что `*` в каждой
/// переменной значит «без ограничения». Этот крейт не даёт настройки под
/// произвольный шаблон или под ограничение цели — так же, как и у
/// CONNECT-UDP ([`crate::request`]), только здесь ограничивать и нечего:
/// весь смысл направления уровня пакетов — пропускать любой адрес.
const PATH_FULL_TUNNEL: &str = "/.well-known/masque/ip/*/*/";

/// Значение заголовка, которым обе стороны включают протокол капсул
/// (RFC 9297, §3.2).
const CAPSULE_PROTOCOL_CONFIRMED: &str = "?1";

/// Собирает текст запроса (RFC 9484, §4.2, Figure 2).
pub(super) fn request_text(host_header: &str, authorization: Option<&str>) -> String {
    let mut text = format!(
        "GET {PATH_FULL_TUNNEL} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: connect-ip\r\n\
         Capsule-Protocol: {CAPSULE_PROTOCOL_CONFIRMED}\r\n"
    );
    if let Some(value) = authorization {
        text.push_str(&format!("Authorization: {value}\r\n"));
    }
    text.push_str("\r\n");
    text
}

/// Проверяет заголовок ответа (RFC 9484, §4.3, Figure 3).
///
/// `head` — всё до пустой строки, без неё самой.
pub(super) fn check_response(head: &str) -> MasqueResult<()> {
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| MasqueError::malformed("пустой ответ"))?;
    let status = parse_status(status_line)?;

    if status != 101 {
        return Err(outcome(status));
    }

    let mut upgraded = false;
    let mut confirmed = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "upgrade" => upgraded = value.eq_ignore_ascii_case("connect-ip"),
            "capsule-protocol" => confirmed = value == CAPSULE_PROTOCOL_CONFIRMED,
            _ => {}
        }
    }

    if !upgraded {
        return Err(MasqueError::malformed(
            "ответ 101 без заголовка `Upgrade: connect-ip`",
        ));
    }
    if !confirmed {
        return Err(MasqueError::malformed(
            "ответ 101 без заголовка `capsule-protocol: ?1`",
        ));
    }
    Ok(())
}

fn parse_status(status_line: &str) -> MasqueResult<u16> {
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| MasqueError::malformed(format!("код ответа не разобрать: `{status_line}`")))
}

/// Ошибка, соответствующая коду ответа, когда апгрейд не удался.
fn outcome(status: u16) -> MasqueError {
    match status {
        401 | 407 => MasqueError::AuthRejected { status },
        other => MasqueError::RefusedIp { status: other },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_asks_for_the_full_tunnel_wildcard() {
        let text = request_text("proxy.example.com", None);
        assert!(
            text.starts_with("GET /.well-known/masque/ip/*/*/ HTTP/1.1\r\n"),
            "{text}"
        );
        assert!(text.contains("Host: proxy.example.com\r\n"), "{text}");
        assert!(text.contains("Connection: Upgrade\r\n"), "{text}");
        assert!(text.contains("Upgrade: connect-ip\r\n"), "{text}");
        assert!(text.contains("Capsule-Protocol: ?1\r\n"), "{text}");
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn authorization_is_attached_when_configured() {
        let text = request_text("proxy.example.com", Some("Bearer секрет-токен"));
        assert!(
            text.contains("Authorization: Bearer секрет-токен\r\n"),
            "{text}"
        );
    }

    #[test]
    fn no_authorization_header_without_configuration() {
        let text = request_text("proxy.example.com", None);
        assert!(!text.contains("Authorization"));
    }

    #[test]
    fn a_good_response_passes() {
        let head = "HTTP/1.1 101 Switching Protocols\r\n\
                     Connection: Upgrade\r\n\
                     Upgrade: connect-ip\r\n\
                     Capsule-Protocol: ?1";
        check_response(head).expect("ответ верный");
    }

    #[test]
    fn header_names_and_the_upgrade_value_are_case_insensitive() {
        let head = "HTTP/1.1 101 Switching Protocols\r\n\
                     upgrade: Connect-IP\r\n\
                     CAPSULE-PROTOCOL: ?1";
        check_response(head).expect("ответ верный");
    }

    #[test]
    fn an_ordinary_web_page_is_a_refusal_not_a_malformed_response() {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/html";
        let err = check_response(head).expect_err("не 101");
        assert!(
            matches!(err, MasqueError::RefusedIp { status: 200 }),
            "{err}"
        );
    }

    #[test]
    fn a_401_is_told_apart_from_a_refusal() {
        let head = "HTTP/1.1 401 Unauthorized\r\n";
        let err = check_response(head).expect_err("не подтверждено");
        assert!(
            matches!(err, MasqueError::AuthRejected { status: 401 }),
            "{err}"
        );
    }

    #[test]
    fn a_101_without_the_capsule_header_is_malformed() {
        let head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: connect-ip";
        let err = check_response(head).expect_err("нет capsule-protocol");
        assert!(err.to_string().contains("capsule-protocol"), "{err}");
    }

    #[test]
    fn a_101_without_upgrade_is_malformed() {
        let head = "HTTP/1.1 101 Switching Protocols\r\nCapsule-Protocol: ?1";
        assert!(check_response(head).is_err());
    }
}
