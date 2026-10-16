//! WireGuard — описание формы.

use crate::forms::check;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Зарезервированных байт нет (нужны единицам, правятся в файле), переключателя
/// UDP тоже: через направление идут пакеты.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::secret("private_key", &["private_key"], |s| s.private_key)
        .required(|s| s.need_private_key),
    // Не секрет: публичный ключ сверяют глазами с присланным.
    FieldSpec::text("server_public_key", &["server_public_key"], |s| {
        s.server_public_key
    })
    .required(|s| s.need_server_public_key),
    FieldSpec::secret("preshared_key", &["preshared_key"], |s| s.preshared_key)
        .example(|s| s.optional_hint),
    FieldSpec::text("address_ipv4", &["address_ipv4"], |s| s.interface_address)
        .example(|s| s.interface_address_example)
        .required(|s| s.need_interface_address),
    FieldSpec::text("address_ipv6", &["address_ipv6"], |s| {
        s.interface_address_v6
    })
    .example(|s| s.optional_hint),
    // Без него имена разрешать нечем, а спрашивать снаружи нельзя.
    FieldSpec::text("dns", &["dns"], |s| s.tunnel_dns).example(|s| s.tunnel_dns_example),
    FieldSpec::text("mtu", &["mtu"], |s| s.mtu).example(|s| s.mtu_example),
    FieldSpec::text("keepalive_secs", &["keepalive_secs"], |s| s.keepalive)
        .example(|s| s.keepalive_example),
];

/// Описание протокола. Ссылок нет: профиль переносят файлом `wg-quick`.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "wireguard",
    label: "WireGuard",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    note: None,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_key_is_not_hidden_but_the_private_one_is() {
        let private = FIELDS
            .iter()
            .find(|field| field.key == "private_key")
            .expect("поле есть");
        let public = FIELDS
            .iter()
            .find(|field| field.key == "server_public_key")
            .expect("поле есть");

        assert!(private.is_secret());
        assert!(!public.is_secret());
    }

    #[test]
    fn the_preshared_key_is_optional_and_hidden() {
        let field = FIELDS
            .iter()
            .find(|field| field.key == "preshared_key")
            .expect("поле есть");
        assert!(field.required.is_none());
        assert!(field.is_secret());
    }

    #[test]
    fn the_interface_address_is_required_because_the_server_will_not_tell_it() {
        let field = FIELDS
            .iter()
            .find(|field| field.key == "address_ipv4")
            .expect("поле есть");
        assert!(field.required.is_some());
    }

    #[test]
    fn the_reserved_bytes_are_not_in_the_form() {
        assert!(FIELDS.iter().all(|field| field.key != "reserved"));
    }
}
