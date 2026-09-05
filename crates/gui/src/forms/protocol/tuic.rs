//! TUIC — описание формы.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 443;

/// Чем QUIC управляет перегрузкой.
///
/// Первое — умолчание нового профиля. `bbr` сверху потому, что он держится
/// лучше остальных там, где потери не означают перегрузку, — а именно так
/// ведёт себя мобильная сеть.
const CONGESTION: &[&str] = &["bbr", "cubic", "new_reno"];

/// Чем едут датаграммы.
///
/// `native` — датаграммами QUIC: быстро и без порядка, то есть так, как UDP и
/// устроен. `quic` — потоками: медленнее, зато проходит там, где датаграммы
/// режут по дороге.
const UDP_MODES: &[&str] = &["native", "quic"];

/// Поля формы в том порядке, в каком они показываются.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::secret("uuid", &["uuid"], |s| s.uuid)
        .required(|s| s.need_uuid)
        .check(check::uuid),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    FieldSpec::choice("congestion", &["congestion"], |s| s.congestion, CONGESTION),
    FieldSpec::choice("udp_mode", &["udp_mode"], |s| s.udp_mode, UDP_MODES),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "tuic",
    label: "TUIC",
    fields: FIELDS,
    schemes: &["tuic://"],
    from_link: Some(from_link),
    note: None,
};

/// Как ссылка ложится в поля.
///
/// ```text
///  tuic://uuid:пароль@хост:порт?sni=…&congestion_control=bbr&udp_relay_mode=native#имя
/// ```
///
/// Двоеточие в userinfo — **разделитель**: слева UUID, справа пароль. Этим
/// ссылка похожа на `socks5://` и не похожа на `trojan://`, где двоеточие
/// принадлежит паролю целиком.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let userinfo = link.userinfo();
    let Some((uuid, password)) = userinfo.split_once(':') else {
        // Без пароля профиль не соберётся: из него выводится отпечаток.
        return Err(crate::i18n::s().link_no_password.to_owned());
    };
    if uuid.is_empty() {
        return Err(crate::i18n::s().link_no_uuid.to_owned());
    }
    if password.is_empty() {
        return Err(crate::i18n::s().link_no_password.to_owned());
    }

    let mut values = vec![
        ("server", link.server(DEFAULT_PORT)),
        ("uuid", uuid.to_owned()),
        ("password", password.to_owned()),
    ];

    if let Some(sni) = link.query.get("sni") {
        values.push(("sni", sni));
    }
    if let Some(congestion) = link.query.get("congestion_control") {
        values.push(("congestion", congestion));
    }
    if let Some(mode) = link.query.get("udp_relay_mode") {
        values.push(("udp_mode", mode));
    }
    if link.query.flag("allow_insecure") || link.query.flag("allowInsecure") {
        values.push(("insecure", "1".to_owned()));
    }

    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::link;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

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
    fn a_plain_link_fills_everything_it_should() {
        let values = parse(&format!("tuic://{UUID}:secret@example.com:8443#Дом"));
        assert_eq!(value(&values, "server"), Some("example.com:8443"));
        assert_eq!(value(&values, "uuid"), Some(UUID));
        assert_eq!(value(&values, "password"), Some("secret"));
    }

    #[test]
    fn the_colon_splits_the_uuid_from_the_password() {
        // Не как у Trojan: там двоеточие принадлежит паролю целиком, а здесь
        // это разделитель — и первое двоеточие отделяет ровно UUID.
        let values = parse(&format!("tuic://{UUID}:раз:два@example.com:443"));
        assert_eq!(value(&values, "uuid"), Some(UUID));
        assert_eq!(value(&values, "password"), Some("раз:два"));
    }

    #[test]
    fn a_link_without_a_password_is_refused() {
        let link = link::split(&format!("tuic://{UUID}@example.com:443")).expect("разбирается");
        assert!(from_link(&link).is_err());

        let link = link::split(&format!("tuic://{UUID}:@example.com:443")).expect("разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn a_link_without_a_uuid_is_refused() {
        let link = link::split("tuic://:secret@example.com:443").expect("разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn the_settings_from_the_query_are_carried_over() {
        let values = parse(&format!(
            "tuic://{UUID}:secret@example.com:443?sni=cdn.example.com&congestion_control=cubic&udp_relay_mode=quic"
        ));
        assert_eq!(value(&values, "sni"), Some("cdn.example.com"));
        assert_eq!(value(&values, "congestion"), Some("cubic"));
        assert_eq!(value(&values, "udp_mode"), Some("quic"));
    }

    #[test]
    fn both_spellings_of_skipping_the_check_are_understood() {
        for raw in [
            format!("tuic://{UUID}:secret@example.com:443?allow_insecure=1"),
            format!("tuic://{UUID}:secret@example.com:443?allowInsecure=1"),
        ] {
            assert_eq!(value(&parse(&raw), "insecure"), Some("1"), "{raw}");
        }
    }

    #[test]
    fn a_link_without_extras_leaves_the_defaults_alone() {
        let values = parse(&format!("tuic://{UUID}:secret@example.com:443"));
        assert!(value(&values, "congestion").is_none());
        assert!(value(&values, "udp_mode").is_none());
        assert!(value(&values, "insecure").is_none());
    }
}
