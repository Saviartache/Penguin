//! Hysteria 2 — описание формы. Имена полей совпадают с конфигурацией
//! официального клиента.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 443;

static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::secret("password", &["password"], |s| s.password)
        .required(|s| s.need_password)
        // `auth` — имя поля в конфигурации провайдера.
        .also(&[&["auth"]]),
    FieldSpec::text("down", &["bandwidth", "down"], |s| s.bandwidth_down)
        .example(|s| s.bandwidth_down_example),
    FieldSpec::text("up", &["bandwidth", "up"], |s| s.bandwidth_up)
        .example(|s| s.bandwidth_up_example),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::secret("obfs", &["obfs", "password"], |s| s.obfs)
        .example(|s| s.obfs_example)
        // Salamander — единственный тип, без него пароль не значит ничего.
        .with(&[(&["obfs", "type"], "salamander")]),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "hysteria2",
    label: "Hysteria 2",
    fields: FIELDS,
    schemes: &["hy2://", "hysteria2://"],
    from_link: Some(from_link),
};

/// Как ссылка ложится в поля.
///
/// Двоеточие в userinfo — часть пароля: в `hy2://source:s3cret@…` пароль
/// `source:s3cret`. `alpn` пропускается: Hysteria 2 ходит только по `h3`.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let password = link.userinfo();
    if password.is_empty() {
        return Err(crate::i18n::s().link_no_password.to_owned());
    }

    let mut values = vec![
        ("server", link.server(DEFAULT_PORT)),
        ("password", password),
    ];
    if let Some(sni) = link.query.get("sni") {
        values.push(("sni", sni));
    }
    if let Some(obfs) = link.query.get("obfs-password") {
        values.push(("obfs", obfs));
    }
    if link.query.flag("insecure") || link.query.flag("allowinsecure") {
        values.push(("insecure", "1".to_owned()));
    }
    Ok(values)
}
