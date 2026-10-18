//! Разбор файла `wg-quick`/AmneziaWG (`.conf`) в [`RawOutbound`].
//!
//! Единичный экспорт из Amnezia — это `.conf`: секции `[Interface]` и `[Peer]`,
//! строки `Ключ = значение`. Поля обфускации (`Jc`, `H1`, `I1`,
//! `HeaderProtectionKey`…) переносятся в блок `amnezia`, проверяет их
//! `protocols/wireguard`. Таймеры AWG 3 (`RekeyAfterTime` и прочие) — местная
//! политика клиента: не переносятся. Чистый разбор без сети.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::error::{ConfigError, ConfigResult};
use crate::schema::outbound::RawOutbound;

/// Целочисленные параметры обфускации: ключ в `.conf` (в нижнем регистре) → поле Penguin.
const NUMERIC: &[(&str, &str)] = &[
    ("jc", "jc"),
    ("jmin", "jmin"),
    ("jmax", "jmax"),
    ("s1", "s1"),
    ("s2", "s2"),
    ("s3", "s3"),
    ("s4", "s4"),
];

/// Строковые параметры как есть: заголовки и добавка (число либо `lo-hi`),
/// сигнатуры `I1`–`I5`, ключ защиты заголовков (base64).
const TEXT: &[(&str, &str)] = &[
    ("h1", "h1"),
    ("h2", "h2"),
    ("h3", "h3"),
    ("h4", "h4"),
    ("i1", "i1"),
    ("i2", "i2"),
    ("i3", "i3"),
    ("i4", "i4"),
    ("i5", "i5"),
    ("headerprotectionkey", "header_protection_key"),
    ("contentpaddingaddition", "content_padding_addition"),
];

/// Разбирает `.conf` в описание направления `wireguard`.
pub fn parse_wireguard_conf(text: &str) -> ConfigResult<RawOutbound> {
    let (interface, peer) = sections(text);

    let private_key = required(&interface, "privatekey")?;
    let server_public_key = required(&peer, "publickey")?;
    let endpoint = required(&peer, "endpoint")?;
    let address = required(&interface, "address")?;

    let mut params = Map::new();
    params.insert("server".into(), json!(endpoint));
    params.insert("private_key".into(), json!(private_key));
    params.insert("server_public_key".into(), json!(server_public_key));

    let (ipv4, ipv6) = split_addresses(&address);
    let ipv4 = ipv4.ok_or_else(|| invalid("в `[Interface] Address` нет адреса IPv4"))?;
    params.insert("address_ipv4".into(), json!(ipv4));
    if let Some(ipv6) = ipv6 {
        params.insert("address_ipv6".into(), json!(ipv6));
    }

    if let Some(psk) = peer.get("presharedkey").filter(|value| !value.is_empty()) {
        params.insert("preshared_key".into(), json!(psk));
    }
    if let Some(dns) = interface.get("dns").filter(|value| !value.is_empty()) {
        let servers: Vec<&str> = dns
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        params.insert("dns".into(), json!(servers));
    }
    if let Some(mtu) = integer(&interface, "mtu") {
        params.insert("mtu".into(), json!(mtu));
    }
    if let Some(keepalive) = integer(&peer, "persistentkeepalive") {
        params.insert("keepalive_secs".into(), json!(keepalive));
    }

    let amnezia = obfuscation(&interface)?;
    if !amnezia.is_empty() {
        params.insert("amnezia".into(), Value::Object(amnezia));
    }

    Ok(RawOutbound::new("wireguard", Value::Object(params)))
}

/// Делит файл на `[Interface]` и первый `[Peer]`; ключи — в нижнем регистре.
fn sections(text: &str) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut interface = BTreeMap::new();
    let mut peer = BTreeMap::new();
    let mut in_peer = false;
    let mut peer_seen = false;

    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            match name.trim().to_ascii_lowercase().as_str() {
                "interface" => in_peer = false,
                "peer" => {
                    // Только первый пир: у единичного экспорта он один.
                    if peer_seen {
                        break;
                    }
                    in_peer = true;
                    peer_seen = true;
                }
                _ => {}
            }
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_owned();
            let target = if in_peer { &mut peer } else { &mut interface };
            target.insert(key, value);
        }
    }
    (interface, peer)
}

/// Обязательное непустое поле.
fn required(map: &BTreeMap<String, String>, key: &str) -> ConfigResult<String> {
    map.get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| invalid(format!("в `.conf` нет `{key}`")))
}

/// Делит `Address` на первый IPv4 и первый IPv6 (с длиной префикса).
fn split_addresses(address: &str) -> (Option<String>, Option<String>) {
    let mut ipv4 = None;
    let mut ipv6 = None;
    for part in address.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let head = part.split('/').next().unwrap_or(part);
        if head.parse::<std::net::Ipv4Addr>().is_ok() {
            ipv4.get_or_insert_with(|| part.to_owned());
        } else if head.parse::<std::net::Ipv6Addr>().is_ok() {
            ipv6.get_or_insert_with(|| part.to_owned());
        }
    }
    (ipv4, ipv6)
}

/// Блок `amnezia` из полей обфускации.
fn obfuscation(interface: &BTreeMap<String, String>) -> ConfigResult<Map<String, Value>> {
    let mut amnezia = Map::new();
    for (conf_key, field) in NUMERIC {
        if let Some(value) = integer(interface, conf_key) {
            amnezia.insert((*field).to_owned(), json!(value));
        }
    }
    for (conf_key, field) in TEXT {
        if let Some(value) = interface.get(*conf_key).filter(|value| !value.is_empty()) {
            amnezia.insert((*field).to_owned(), json!(value));
        }
    }
    if let Some(text) = interface
        .get("randomtrailers")
        .filter(|value| !value.is_empty())
    {
        amnezia.insert("random_trailers".to_owned(), json!(boolean(text)?));
    }
    Ok(amnezia)
}

/// Логическое значение, как `strconv.ParseBool` эталона.
fn boolean(text: &str) -> ConfigResult<bool> {
    match text {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        other => Err(invalid(format!(
            "`RandomTrailers` не логическое: `{other}`"
        ))),
    }
}

/// Целое поле.
fn integer(map: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    map.get(key)?.trim().parse().ok()
}

/// Ошибка разбора `.conf`.
fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::invalid("wireguard.conf", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AWG: &str = "\
[Interface]
Address = 10.8.1.2/32, fd00::2/128
DNS = 1.1.1.1, 8.8.8.8
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
MTU = 1420
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
H1 = 1162604561
H2 = 2130573662
H3 = 3173116691
H4 = 4094540177

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
PresharedKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = nl.example.com:51820
PersistentKeepalive = 25
";

    #[test]
    fn an_amneziawg_conf_becomes_a_wireguard_outbound() {
        let outbound = parse_wireguard_conf(AWG).expect("разбор");
        assert_eq!(outbound.protocol, "wireguard");
        let p = &outbound.params;
        assert_eq!(p["server"], "nl.example.com:51820");
        assert_eq!(p["address_ipv4"], "10.8.1.2/32");
        assert_eq!(p["address_ipv6"], "fd00::2/128");
        assert_eq!(p["dns"], json!(["1.1.1.1", "8.8.8.8"]));
        assert_eq!(p["mtu"], 1420);
        assert_eq!(p["keepalive_secs"], 25);
        assert_eq!(p["amnezia"]["jc"], 4);
        assert_eq!(p["amnezia"]["h1"], "1162604561");
        assert!(p["amnezia"].get("s2").is_none(), "пустые не переносятся");
    }

    #[test]
    fn a_plain_wireguard_conf_has_no_amnezia_block() {
        let conf = "\
[Interface]
Address = 10.0.0.2/32
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 1.2.3.4:51820
";
        let outbound = parse_wireguard_conf(conf).expect("разбор");
        assert!(outbound.params.get("amnezia").is_none());
        assert!(outbound.params.get("preshared_key").is_none());
    }

    #[test]
    fn comments_and_case_are_tolerated() {
        let conf = "\
[interface]
address = 10.0.0.2/32  # адрес клиента
privatekey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
[peer]
publickey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
endpoint = 1.2.3.4:51820
";
        assert!(parse_wireguard_conf(conf).is_ok());
    }

    #[test]
    fn an_awg_3_conf_carries_its_fields_into_the_amnezia_block() {
        let conf = AWG.replace(
            "Jc = 4",
            "Jc = 4\nI1 = <b 0xc0ffee><r 16>\nI2 = <rc 8>\n\
             HeaderProtectionKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
             ContentPaddingAddition = 8-32\nRandomTrailers = true",
        );
        let outbound = parse_wireguard_conf(&conf).expect("разбор");
        let amnezia = &outbound.params["amnezia"];
        assert_eq!(amnezia["i1"], "<b 0xc0ffee><r 16>");
        assert_eq!(amnezia["i2"], "<rc 8>");
        assert_eq!(
            amnezia["header_protection_key"],
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
        );
        assert_eq!(amnezia["content_padding_addition"], "8-32");
        assert_eq!(amnezia["random_trailers"], true);
    }

    #[test]
    fn a_non_boolean_random_trailers_is_refused() {
        let conf = AWG.replace("Jc = 4", "Jc = 4\nRandomTrailers = maybe");
        let error = parse_wireguard_conf(&conf).expect_err("не bool");
        assert!(error.to_string().contains("RandomTrailers"), "{error}");
    }

    #[test]
    fn a_conf_without_a_peer_key_is_refused() {
        let conf = "\
[Interface]
Address = 10.0.0.2/32
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
[Peer]
Endpoint = 1.2.3.4:51820
";
        assert!(parse_wireguard_conf(conf).is_err());
    }

    #[test]
    fn only_the_first_peer_is_read() {
        let conf = "\
[Interface]
Address = 10.0.0.2/32
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 1.2.3.4:51820
[Peer]
PublicKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=
Endpoint = 9.9.9.9:51820
";
        let outbound = parse_wireguard_conf(conf).expect("разбор");
        assert_eq!(outbound.params["server"], "1.2.3.4:51820");
    }
}
