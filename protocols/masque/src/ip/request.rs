//! Запрос `CONNECT-IP`: расширенный `CONNECT` поверх HTTP/3 (RFC 9484,
//! §4.4–4.5).

use penguin_transport::h3;

use crate::error::{MasqueError, MasqueResult};

/// Значение `:protocol` расширенного `CONNECT` (§4.4).
const PROTOCOL_CONNECT_IP: &str = "connect-ip";

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

/// Собирает запрос (§4.4, Figure 4).
pub(super) fn request(authority: &str, authorization: Option<&str>) -> h3::Request {
    let request = h3::Request::extended_connect(PROTOCOL_CONNECT_IP, authority, PATH_FULL_TUNNEL)
        .header("capsule-protocol", CAPSULE_PROTOCOL_CONFIRMED);
    match authorization {
        Some(value) => request.header("authorization", value),
        None => request,
    }
}

/// Проверяет ответ (§4.5): код `2xx` и подтверждённый протокол капсул.
pub(super) fn check_response(response: &h3::Response) -> MasqueResult<()> {
    let status = response.status();
    if !(200..300).contains(&status) {
        return Err(outcome(status));
    }
    if response.header("capsule-protocol") != Some(CAPSULE_PROTOCOL_CONFIRMED) {
        return Err(MasqueError::malformed(
            "ответ 2xx без заголовка `capsule-protocol: ?1`",
        ));
    }
    Ok(())
}

/// Ошибка, соответствующая коду ответа, когда прокси отказал.
fn outcome(status: u16) -> MasqueError {
    match status {
        401 | 407 => MasqueError::AuthRejected { status },
        other => MasqueError::RefusedIp { status: other },
    }
}

#[cfg(test)]
mod tests {
    use penguin_transport::h3::qpack::{Field, field};

    use super::*;

    fn fields(request: &h3::Request) -> Vec<(String, String)> {
        field::decode(&request.encode(), usize::MAX)
            .expect("разбирается")
            .into_iter()
            .map(|f| {
                let text = |b: Vec<u8>| String::from_utf8(b).expect("текст");
                (text(f.name), text(f.value))
            })
            .collect()
    }

    fn response(status: &str, capsule: bool) -> h3::Response {
        let mut fields = vec![Field {
            name: b":status".to_vec(),
            value: status.as_bytes().to_vec(),
        }];
        if capsule {
            fields.push(Field {
                name: b"capsule-protocol".to_vec(),
                value: b"?1".to_vec(),
            });
        }
        h3::Response::from_fields(fields).expect("ответ верен")
    }

    #[test]
    fn the_request_matches_figure_4() {
        // RFC 9484, §4.4, Figure 4.
        let fields = fields(&request("example.org", None));
        let expected = [
            (":method", "CONNECT"),
            (":protocol", "connect-ip"),
            (":scheme", "https"),
            (":authority", "example.org"),
            (":path", "/.well-known/masque/ip/*/*/"),
            ("capsule-protocol", "?1"),
        ];
        for (name, value) in expected {
            assert!(
                fields.contains(&(name.to_owned(), value.to_owned())),
                "{name}: {fields:?}"
            );
        }
        assert!(!fields.iter().any(|(name, _)| name == "authorization"));
    }

    #[test]
    fn authorization_is_attached_when_configured() {
        let fields = fields(&request("example.org", Some("Bearer секрет-токен")));
        assert!(fields.contains(&("authorization".to_owned(), "Bearer секрет-токен".to_owned())));
    }

    #[test]
    fn responses_are_checked_like_figure_5() {
        check_response(&response("200", true)).expect("Figure 5");
        assert!(check_response(&response("200", false)).is_err());
        assert!(matches!(
            check_response(&response("407", true)),
            Err(MasqueError::AuthRejected { status: 407 })
        ));
        // 3xx — тоже отказ (§4.5).
        assert!(matches!(
            check_response(&response("302", true)),
            Err(MasqueError::RefusedIp { status: 302 })
        ));
    }
}
