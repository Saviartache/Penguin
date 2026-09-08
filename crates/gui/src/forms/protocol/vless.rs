//! VLESS — описание формы.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 443;

/// Чем шифруется соединение до сервера.
///
/// `tls` первым: это обычный случай. `none` законен ровно тогда, когда TLS
/// снимает кто-то другой — сеть доставки перед сервером; сам по себе он
/// означает, что UUID уходит по сети открытым текстом.
///
/// `reality` — рукопожатие доведено до прикладных ключей TLS 1.3, и канал
/// несёт байты VLESS (`penguin_vless::reality::handshake::connect`). Но
/// «подключилось» здесь ещё не значит «сервер нас узнал»: сама формула
/// Reality сверена только между `Xray-core` и `sing-box`, без официальных
/// тестовых векторов, — не узнавший клиента сервер не откажет, а молча
/// перешлёт его настоящему сайту. Об этом форма говорит отдельной строкой
/// (`SPEC.note`, `crate::i18n::Strings::reality_unverified`), а не молчит.
const SECURITY: &[&str] = &["tls", "none", "reality"];

/// Чем переносится поток.
const TRANSPORTS: &[&str] = &["tcp", "ws", "httpupgrade"];

/// Поля формы в том порядке, в каком они показываются.
///
/// Поля Reality (`reality_*`) не помечены `.required()`, хотя без них
/// `security = "reality"` не поднимется, — конфликта с `tls`/`none` тогда бы
/// не было, потому что этой форме нечем спросить «обязательно, только если
/// security = reality» (`FieldSpec::required` не видит других полей). Как и
/// у `path`/`host` под `ws`/`httpupgrade`, недостающее здесь ловит
/// `RealityConfig::validate` — понятной ошибкой, а не пустым ключом сервера.
///
/// Отпечатка браузера (`penguin_utls::Fingerprint`) в форме нет нарочно:
/// поле выбора не умеет быть пустым (`FieldSpec::choice`, см. `spec.rs`) и
/// писало бы `reality.fingerprint` даже в профиль `tls`/`none`, заводя
/// группу `reality`, которой там взяться неоткуда, — `RealityConfig` и так
/// по умолчанию берёт `chrome` (`config.rs`), и ссылка `fp=` от провайдера
/// сюда не заводится по той же причине.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::secret("uuid", &["uuid"], |s| s.uuid)
        .required(|s| s.need_uuid)
        .check(check::uuid),
    FieldSpec::choice("security", &["security"], |s| s.security, SECURITY),
    FieldSpec::choice("transport", &["transport"], |s| s.transport, TRANSPORTS),
    // Свободный текст, а не выбор: единственное принимаемое значение —
    // `penguin_vless::frame::addons::FLOW_VISION`, а поле выбора не умеет
    // быть пустым (см. документ `FIELDS` про отпечаток чуть ниже) — здесь же
    // пустое как раз законное и самое частое значение. Неверную комбинацию
    // (не та `security`, не тот `transport`, не то значение) ловит
    // `VlessConfig::validate` понятной ошибкой, а не эта форма.
    FieldSpec::text("flow", &["flow"], |s| s.flow).example(|s| s.flow_example),
    FieldSpec::text("path", &["path"], |s| s.path).example(|s| s.path_example),
    FieldSpec::text("host", &["host"], |s| s.http_host).example(|s| s.optional_hint),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
    FieldSpec::text("reality_public_key", &["reality", "public_key"], |s| {
        s.server_public_key
    })
    .example(|s| s.reality_public_key_example),
    FieldSpec::text("reality_short_id", &["reality", "short_id"], |s| {
        s.reality_short_id
    })
    .example(|s| s.reality_short_id_example),
    FieldSpec::text("reality_server_name", &["reality", "server_name"], |s| {
        s.reality_server_name
    })
    .example(|s| s.reality_server_name_example),
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "vless",
    label: "VLESS",
    fields: FIELDS,
    schemes: &["vless://"],
    from_link: Some(from_link),
    // Строка не про VLESS вообще, а про security = reality — см. документ
    // константы `SECURITY` и `crate::i18n::Strings::reality_unverified`.
    // Показывать её и при tls/none тоже — цена статичной строки в этой
    // форме: другого способа сказать это только при выборе reality сейчас
    // нет (`FieldKind::Choice` не показывает `example`, см. `editor.rs`).
    note: Some(|s| s.reality_unverified),
};

/// Как ссылка ложится в поля.
///
/// ```text
///  vless://uuid@хост:порт?encryption=none&security=tls&type=ws&path=/…#имя
/// ```
///
/// `encryption` в ссылке всегда `none` и означает не «без шифрования», а
/// «своего шифрования у протокола нет». Поля под него в форме нет: другого
/// значения не бывает, а показывать переключатель с одним положением — значит
/// спрашивать о том, чего не выбирают.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let uuid = link.userinfo();
    if uuid.is_empty() {
        return Err(crate::i18n::s().link_no_uuid.to_owned());
    }

    let mut values = vec![("server", link.server(DEFAULT_PORT)), ("uuid", uuid)];

    let is_reality = link.query.get("security").as_deref() == Some("reality");
    if let Some(security) = link.query.get("security") {
        values.push(("security", security));
    }
    if let Some(transport) = link.query.get("type") {
        values.push(("transport", transport));
    }
    if let Some(path) = link.query.get("path") {
        values.push(("path", path));
    }
    if let Some(host) = link.query.get("host") {
        values.push(("host", host));
    }
    // Одно и то же имя сайта у обычного TLS (`tls.sni`) и у Reality
    // (`reality.server_name`) значит разное — совсем не подделка личности
    // против ровно этой подделки — и лежит в разных полях
    // (`RealityConfig::validate` отказывает, если заданы оба сразу).
    if let Some(sni) = link.query.get("sni").or_else(|| link.query.get("peer")) {
        values.push((
            if is_reality {
                "reality_server_name"
            } else {
                "sni"
            },
            sni,
        ));
    }
    if link.query.flag("allowInsecure") || link.query.flag("insecure") {
        values.push(("insecure", "1".to_owned()));
    }
    // `pbk`/`sid` — обычные имена параметров Reality в ссылках `vless://`
    // (`Xray-core`, `infra/conf/transport_security.go`, разбор `RealityOpts`).
    // Отпечаток (`fp`) сюда не попадает — поля под него в форме нет (см.
    // документ `FIELDS`), и ссылка с ним просто оставляет умолчание `chrome`.
    if let Some(public_key) = link.query.get("pbk") {
        values.push(("reality_public_key", public_key));
    }
    if let Some(short_id) = link.query.get("sid") {
        values.push(("reality_short_id", short_id));
    }
    if let Some(flow) = link.query.get("flow") {
        values.push(("flow", flow));
    }

    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::link;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn reality_is_offered_now_that_the_handshake_carries_traffic() {
        // Рукопожатие доведено до прикладных ключей TLS 1.3
        // (`penguin_vless::reality::handshake::connect`) — канал несёт байты
        // VLESS, и пункт в списке снова можно выбрать с пользой.
        assert!(SECURITY.contains(&"reality"));
    }

    #[test]
    fn the_form_warns_that_reality_was_not_checked_against_a_live_server() {
        assert!(SPEC.note.is_some());
    }

    #[test]
    fn the_flow_field_is_exposed_in_the_form() {
        assert!(SPEC.index_of("flow").is_some());
    }

    fn parse(raw: &str) -> Vec<(&'static str, String)> {
        let link = link::split(raw).expect("ссылка разбирается");
        from_link(&link).expect("поля заполняются")
    }

    fn value<'a>(values: &'a [(&'static str, String)], key: &str) -> Option<&'a str> {
        values
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn a_plain_link_fills_the_address_and_the_uuid() {
        let values = parse(&format!("vless://{UUID}@example.com:8443#Дом"));
        assert_eq!(value(&values, "server"), Some("example.com:8443"));
        assert_eq!(value(&values, "uuid"), Some(UUID));
    }

    #[test]
    fn the_port_defaults_to_the_one_a_site_would_use() {
        let values = parse(&format!("vless://{UUID}@example.com"));
        assert_eq!(value(&values, "server"), Some("example.com:443"));
    }

    #[test]
    fn a_link_without_a_uuid_is_refused() {
        let link = link::split("vless://example.com:443").expect("разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn the_websocket_settings_are_carried_over() {
        let values = parse(&format!(
            "vless://{UUID}@example.com:443?security=tls&type=ws&path=/ws&host=cdn.example.com&sni=cdn.example.com"
        ));
        assert_eq!(value(&values, "security"), Some("tls"));
        assert_eq!(value(&values, "transport"), Some("ws"));
        assert_eq!(value(&values, "path"), Some("/ws"));
        assert_eq!(value(&values, "host"), Some("cdn.example.com"));
        assert_eq!(value(&values, "sni"), Some("cdn.example.com"));
    }

    #[test]
    fn a_vision_flow_is_carried_over_from_the_link() {
        let values = parse(&format!(
            "vless://{UUID}@example.com:443?security=reality&pbk=abc&sid=ab12&sni=www.example.com&flow=xtls-rprx-vision"
        ));
        assert_eq!(value(&values, "flow"), Some("xtls-rprx-vision"));
    }

    #[test]
    fn reality_settings_are_carried_over_into_their_own_fields() {
        let values = parse(&format!(
            "vless://{UUID}@example.com:443?security=reality&pbk=abc&sid=ab12&sni=www.example.com"
        ));
        assert_eq!(value(&values, "security"), Some("reality"));
        assert_eq!(value(&values, "reality_public_key"), Some("abc"));
        assert_eq!(value(&values, "reality_short_id"), Some("ab12"));
        assert_eq!(
            value(&values, "reality_server_name"),
            Some("www.example.com")
        );
        // `sni` (обычный TLS) не заполняется рядом — иначе `RealityConfig::validate`
        // отказала бы: Reality не использует обычный TLS вовсе.
        assert_eq!(value(&values, "sni"), None);
    }

    #[test]
    fn an_unrecognized_security_still_carries_the_site_name_into_plain_sni() {
        // Без `security=reality` имя сайта — это обычный TLS SNI, не Reality.
        let values = parse(&format!(
            "vless://{UUID}@example.com:443?security=tls&sni=cdn.example.com"
        ));
        assert_eq!(value(&values, "sni"), Some("cdn.example.com"));
        assert_eq!(value(&values, "reality_server_name"), None);
    }

    #[test]
    fn a_link_without_extras_leaves_the_defaults_alone() {
        let values = parse(&format!("vless://{UUID}@example.com:443"));
        assert!(value(&values, "transport").is_none());
        assert!(value(&values, "security").is_none());
        assert!(value(&values, "insecure").is_none());
    }
}
