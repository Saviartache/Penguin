//! ShadowsocksR — описание формы.

use crate::forms::check;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Шифры. Умолчания нет: угаданный шифр даёт соединение, которое сервер не
/// расшифрует, и выглядит это молчанием, а не отказом.
///
/// Первым стоит `aes-256-cfb` — самый частый в живых подписках; `none` внизу:
/// он не шифрует вовсе.
const METHODS: &[&str] = &[
    "aes-256-cfb",
    "aes-192-cfb",
    "aes-128-cfb",
    "aes-256-ctr",
    "aes-192-ctr",
    "aes-128-ctr",
    "rc4-md5",
    "none",
];

/// Надстройка `obfs` — внешний вид пакета.
const OBFS: &[&str] = &["plain", "http_simple"];

/// Надстройка `protocol` — формат кадра поверх шифра.
const PROTOCOL_METHODS: &[&str] = &["origin", "auth_aes128_md5", "auth_aes128_sha1"];

/// Поля формы в том порядке, в каком они показываются.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::choice("method", &["method"], |s| s.method, METHODS).required(|s| s.need_method),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    FieldSpec::choice("obfs", &["obfs"], |s| s.obfs, OBFS),
    FieldSpec::text("obfs_param", &["obfs_param"], |s| s.obfs_param)
        .example(|s| s.obfs_param_example),
    // Не `protocol`: этим именем в настройках выбирается сам протокол, и
    // одноимённое поле было бы недостижимо.
    FieldSpec::choice(
        "protocol_method",
        &["protocol_method"],
        |s| s.ssr_protocol,
        PROTOCOL_METHODS,
    ),
];

/// Описание протокола.
///
/// Ссылок нет: запись `ssr://` существует, но это base64 внутри base64 со
/// своим набором параметров, и разбор её здесь пока не написан.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "shadowsocksr",
    label: "ShadowsocksR",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    // Форма во всём остальном похожа на форму Shadowsocks, и молчание здесь
    // выдавало бы одно за другое: там только AEAD, здесь — потоковые шифры,
    // которые данные не заверяют вовсе.
    note: Some(|s| s.ssr_no_authentication),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_frame_field_is_not_called_protocol() {
        // Это имя в настройках занято выбором самого протокола: поле с ним
        // было бы недостижимо, а записанное в него читалось бы как имя
        // протокола. Общая проверка на все протоколы — в `catalog`.
        let field = FIELDS
            .iter()
            .find(|field| field.key == "protocol_method")
            .expect("поле есть");
        assert_eq!(field.path, &["protocol_method"]);
    }

    #[test]
    fn the_form_says_out_loud_that_nothing_is_authenticated() {
        // Форма похожа на форму Shadowsocks, а свойство у протокола другое.
        assert!(SPEC.note.is_some());
    }

    #[test]
    fn the_cipher_is_required_because_it_cannot_be_guessed() {
        let method = FIELDS
            .iter()
            .find(|field| field.key == "method")
            .expect("поле есть");
        assert!(method.required.is_some());
        assert!(method.is_choice(), "шифр набирают руками");
    }

    #[test]
    fn there_is_no_udp_switch_because_there_is_no_udp() {
        assert!(FIELDS.iter().all(|field| field.key != "udp"));
    }
}
