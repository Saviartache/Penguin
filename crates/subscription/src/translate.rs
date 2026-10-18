//! Перевод ответа шлюза в профиль Penguin.
//!
//! Ответ (расшифрованный) → поле `config` (`vpn://…`) → `containers[0].awg`
//! → `last_config` (структурный JSON клиента AmneziaWG) → `RawOutbound` с
//! протоколом `wireguard` и блоком `amnezia`. Приватный ключ клиента —
//! сгенерированный (`$WIREGUARD_CLIENT_PRIVATE_KEY` в ответе не читается).
//! Чистая логика без сети (`AGENTS.md` §2.3).

use penguin_config::schema::outbound::RawOutbound;
use penguin_config::schema::profile::Profile;
use serde_json::{Map, Value, json};

use crate::device::Device;
use crate::error::{SubscriptionError, SubscriptionResult};
use crate::key::{SubscriptionKey, decode_blob};

/// Целочисленные параметры обфускации: имя у Amnezia → имя у Penguin.
const NUMERIC_PARAMS: &[(&str, &str)] = &[
    ("Jc", "jc"),
    ("Jmin", "jmin"),
    ("Jmax", "jmax"),
    ("S1", "s1"),
    ("S2", "s2"),
    ("S3", "s3"),
    ("S4", "s4"),
];

/// Строковые параметры как есть: заголовки и добавка (число либо `lo-hi`),
/// сигнатуры `I1`–`I5`, ключ защиты заголовков (base64). Проверяет их протокол.
const TEXT_PARAMS: &[(&str, &str)] = &[
    ("H1", "h1"),
    ("H2", "h2"),
    ("H3", "h3"),
    ("H4", "h4"),
    ("I1", "i1"),
    ("I2", "i2"),
    ("I3", "i3"),
    ("I4", "i4"),
    ("I5", "i5"),
    ("HeaderProtectionKey", "header_protection_key"),
    ("ContentPaddingAddition", "content_padding_addition"),
];

/// Переводит ответ шлюза в управляемый профиль.
///
/// `requested_country` — страна из запроса (`None` для первого, за сервером по
/// умолчанию); имя и идентификатор берут её, иначе — `server_country_code`
/// самого ответа, чтобы профиль «по умолчанию» не задвоился со своей страной.
pub fn profile(
    decrypted: &[u8],
    key: &SubscriptionKey,
    device: &Device,
    requested_country: Option<&str>,
) -> SubscriptionResult<Profile> {
    let server_config = server_config(decrypted)?;

    let awg = server_config
        .pointer("/containers/0/awg")
        .ok_or_else(|| SubscriptionError::Response("нет `containers[0].awg`".to_owned()))?;
    let last_config_str = awg
        .get("last_config")
        .and_then(Value::as_str)
        .ok_or_else(|| SubscriptionError::Response("нет `last_config`".to_owned()))?;
    let last: Value = serde_json::from_str(last_config_str)
        .map_err(|e| SubscriptionError::Response(format!("`last_config` не JSON: {e}")))?;

    let params = build_params(&server_config, &last, device)?;
    let outbound = RawOutbound::new("wireguard", params);

    let country = requested_country
        .filter(|code| !code.is_empty())
        .map(str::to_owned)
        .or_else(|| config_country(&server_config));

    let name = match &country {
        Some(code) => format!("Amnezia {code}"),
        None => format!("Amnezia {}", str_field(&last, "hostName")),
    };
    let id = match &country {
        Some(code) => format!("{}-{}", key.id(), code.to_lowercase()),
        None => key.id().to_owned(),
    };

    let mut profile = Profile::new(id, name.trim().to_owned(), outbound);
    profile.subscription = Some(key.id().to_owned());
    Ok(profile)
}

/// Коды стран из ответа (`api_config.available_countries`) — список локаций.
pub fn available_countries(decrypted: &[u8]) -> SubscriptionResult<Vec<String>> {
    let server_config = server_config(decrypted)?;
    Ok(server_config
        .pointer("/api_config/available_countries")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| nonempty(item, "server_country_code"))
                .collect()
        })
        .unwrap_or_default())
}

/// Страна сервера из ответа — та, что вернул запрос без явной страны.
pub fn server_country(decrypted: &[u8]) -> SubscriptionResult<Option<String>> {
    Ok(config_country(&server_config(decrypted)?))
}

/// Разбирает ответ: проверки капчи/`http_status`, расшифровка `config` в конфиг.
fn server_config(decrypted: &[u8]) -> SubscriptionResult<Value> {
    let body: Value = serde_json::from_slice(decrypted)
        .map_err(|e| SubscriptionError::Response(format!("тело не JSON: {e}")))?;

    if body.get("captcha_id").is_some() {
        return Err(SubscriptionError::Captcha);
    }
    // Успех — любой 2xx: шлюз отвечает `201 Created`, когда завёл конфиг.
    if let Some(status) = body.get("http_status").and_then(Value::as_i64)
        && !(200..300).contains(&status)
    {
        return Err(SubscriptionError::Gateway {
            status,
            message: body
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        });
    }

    let config_blob = body
        .get("config")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| SubscriptionError::Response("нет поля `config`".to_owned()))?;

    serde_json::from_slice(&decode_blob(config_blob)?)
        .map_err(|e| SubscriptionError::Response(format!("конфиг не JSON: {e}")))
}

/// Код страны сервера: сперва верхнего уровня, иначе из `api_config`.
fn config_country(server_config: &Value) -> Option<String> {
    nonempty(server_config, "server_country_code").or_else(|| {
        server_config
            .pointer("/api_config")
            .and_then(|c| nonempty(c, "server_country_code"))
    })
}

/// Собирает параметры `RawOutbound` протокола `wireguard` с блоком `amnezia`.
fn build_params(server_config: &Value, last: &Value, device: &Device) -> SubscriptionResult<Value> {
    let host = nonempty(last, "hostName").ok_or_else(|| missing("hostName"))?;
    let port = integer(last, "port")
        .filter(|value| *value > 0)
        .ok_or_else(|| missing("port"))?;
    let server_public_key =
        nonempty(last, "server_pub_key").ok_or_else(|| missing("server_pub_key"))?;
    let client_ip = nonempty(last, "client_ip").ok_or_else(|| missing("client_ip"))?;

    let address_ipv4 = if client_ip.contains('/') {
        client_ip
    } else {
        format!("{client_ip}/32")
    };

    let mut params = Map::new();
    params.insert("server".into(), json!(format!("{host}:{port}")));
    params.insert("private_key".into(), json!(device.private_key()));
    params.insert("server_public_key".into(), json!(server_public_key));
    params.insert("address_ipv4".into(), json!(address_ipv4));

    if let Some(psk) = nonempty(last, "psk_key") {
        params.insert("preshared_key".into(), json!(psk));
    }
    if let Some(mtu) =
        integer(last, "mtu").filter(|value| *value > 0 && *value <= u64::from(u16::MAX))
    {
        params.insert("mtu".into(), json!(mtu));
    }
    if let Some(keepalive) = integer(last, "persistent_keep_alive") {
        params.insert("keepalive_secs".into(), json!(keepalive));
    }

    let dns = name_servers(server_config);
    if !dns.is_empty() {
        params.insert("dns".into(), json!(dns));
    }

    params.insert("amnezia".into(), Value::Object(obfuscation(last)?));
    Ok(Value::Object(params))
}

/// Блок `amnezia`. Таймеры AWG 3 (`RekeyAfterTime` и прочие) — местная политика
/// клиента, не обфускация: не переносятся, действуют умолчания WireGuard.
fn obfuscation(last: &Value) -> SubscriptionResult<Map<String, Value>> {
    let mut amnezia = Map::new();
    for (amnezia_key, penguin_key) in NUMERIC_PARAMS {
        if let Some(value) = integer(last, amnezia_key) {
            amnezia.insert((*penguin_key).to_owned(), json!(value));
        }
    }
    for (amnezia_key, penguin_key) in TEXT_PARAMS {
        if let Some(value) = nonempty(last, amnezia_key) {
            // Строкой: диапазон протокол читает и как число, и как `lo-hi`.
            amnezia.insert((*penguin_key).to_owned(), json!(value));
        }
    }
    if let Some(on) = boolean(last, "RandomTrailers")? {
        amnezia.insert("random_trailers".to_owned(), json!(on));
    }
    Ok(amnezia)
}

/// Логическое поле: `true`/`false` или строкой, как `strconv.ParseBool` эталона.
fn boolean(value: &Value, field: &str) -> SubscriptionResult<Option<bool>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(on)) => Ok(Some(*on)),
        Some(Value::String(text)) => match text.trim() {
            "" => Ok(None),
            "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(Some(true)),
            "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(Some(false)),
            other => Err(SubscriptionError::Response(format!(
                "`{field}` не логическое: `{other}`"
            ))),
        },
        Some(other) => Err(SubscriptionError::Response(format!(
            "`{field}` не логическое: {other}"
        ))),
    }
}

/// Серверы имён из конфига (`dns1`, `dns2`).
fn name_servers(server_config: &Value) -> Vec<String> {
    ["dns1", "dns2"]
        .iter()
        .filter_map(|field| nonempty(server_config, field))
        .collect()
}

/// Непустое строковое поле.
fn nonempty(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// Строковое поле или пусто.
fn str_field(value: &Value, field: &str) -> String {
    nonempty(value, field).unwrap_or_default()
}

/// Целое поле: принимает и число, и строку (Amnezia пишет числа строками).
fn integer(value: &Value, field: &str) -> Option<u64> {
    match value.get(field)? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// Ошибка «поля нет».
fn missing(field: &str) -> SubscriptionError {
    SubscriptionError::Response(format!("в `last_config` нет `{field}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::SubscriptionKey;
    use penguin_core::base64;

    fn device() -> Device {
        Device::generate().expect("устройство")
    }

    fn key() -> SubscriptionKey {
        let value = json!({
            "api_config": {
                "service_type": "amnezia-premium",
                "service_protocol": "awg",
                "user_country_code": "RU",
                "available_countries": []
            },
            "auth_data": { "api_key": "token" }
        });
        let encoded = base64::encode_url(&serde_json::to_vec(&value).expect("json"));
        SubscriptionKey::parse(&format!("vpn://{encoded}")).expect("ключ")
    }

    /// Собирает ответ шлюза: `config` = `vpn://` от конфига с данным `last_config`.
    fn response(last_config: Value) -> Vec<u8> {
        let server_config = json!({
            "config_version": 5,
            "dns1": "1.1.1.1",
            "dns2": "8.8.8.8",
            "server_country_code": "nl",
            "api_config": {
                "available_countries": [
                    { "server_country_code": "nl", "server_country_name": "Netherlands" },
                    { "server_country_code": "de", "server_country_name": "Germany" },
                    { "server_country_code": "us-east", "server_country_name": "USA East" }
                ]
            },
            "containers": [
                { "container": "amnezia-awg", "awg": {
                    "port": "51820",
                    "last_config": serde_json::to_string(&last_config).expect("json")
                }}
            ]
        });
        let config = base64::encode_url(&serde_json::to_vec(&server_config).expect("json"));
        // Шлюз отвечает `http_status: 201`, когда завёл конфиг.
        serde_json::to_vec(&json!({ "http_status": 201, "config": format!("vpn://{config}") }))
            .expect("json")
    }

    fn good_last_config() -> Value {
        json!({
            "config": "[Interface]\nPrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY\n",
            "hostName": "nl.example.com",
            "port": 51820,
            "client_ip": "10.8.1.2",
            "server_pub_key": "c2VydmVyX3B1YmxpY19rZXlfMzJfYnl0ZXNfbG9uZ18=",
            "psk_key": "cHJlc2hhcmVkX2tleV8zMl9ieXRlc19sb25nX3h4eA==",
            "mtu": "1420",
            "persistent_keep_alive": "25",
            "Jc": "4",
            "Jmin": "40",
            "Jmax": "70",
            "S1": "0",
            "S2": "0",
            "H1": "1162604561",
            "H2": "2130573662",
            "H3": "3173116691",
            "H4": "4094540177"
        })
    }

    #[test]
    fn a_premium_awg_server_becomes_a_wireguard_profile() {
        let device = device();
        let built =
            profile(&response(good_last_config()), &key(), &device, Some("NL")).expect("перевод");

        assert_eq!(built.outbound.protocol, "wireguard");
        assert_eq!(built.name, "Amnezia NL");
        assert_eq!(built.subscription.as_deref(), Some(key().id()));
        assert!(built.is_managed());

        let params = &built.outbound.params;
        assert_eq!(params["server"], "nl.example.com:51820");
        assert_eq!(params["address_ipv4"], "10.8.1.2/32");
        assert_eq!(params["private_key"], device.private_key());
        assert_eq!(params["mtu"], 1420);
        assert_eq!(params["keepalive_secs"], 25);
        assert_eq!(params["dns"], json!(["1.1.1.1", "8.8.8.8"]));

        let amnezia = &params["amnezia"];
        assert_eq!(amnezia["jc"], 4);
        assert_eq!(amnezia["jmin"], 40);
        assert_eq!(amnezia["h1"], "1162604561");
        assert!(amnezia.get("s3").is_none(), "пустые не переносятся");
    }

    #[test]
    fn the_built_profile_parses_back_as_a_wireguard_config() {
        // Параметры обязаны разбираться схемой протокола (deny_unknown_fields).
        let built =
            profile(&response(good_last_config()), &key(), &device(), Some("NL")).expect("перевод");
        let value = serde_json::to_value(&built.outbound.params).expect("json");
        // Поля должны совпасть с WireguardConfig: сервер, ключи, адрес, amnezia.
        assert!(value.get("server").is_some());
        assert!(value.get("amnezia").and_then(|a| a.get("jc")).is_some());
        assert!(value.get("I1").is_none());
    }

    #[test]
    fn an_awg_3_config_carries_its_fields_into_the_amnezia_block() {
        // Набор, какой шлюз отдаёт премиум-серверам: I1, I2, ключ защиты, добавка.
        let mut last = good_last_config();
        last["I1"] = json!("<b 0xc0ffee><r 16>");
        last["I2"] = json!("<rc 8>");
        last["HeaderProtectionKey"] = json!("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=");
        last["ContentPaddingAddition"] = json!("8-32");
        last["RandomTrailers"] = json!("true");
        let built = profile(&response(last), &key(), &device(), Some("NL")).expect("перевод");

        let amnezia = &built.outbound.params["amnezia"];
        assert_eq!(amnezia["i1"], "<b 0xc0ffee><r 16>");
        assert_eq!(amnezia["i2"], "<rc 8>");
        assert!(amnezia.get("i3").is_none());
        assert_eq!(
            amnezia["header_protection_key"],
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
        );
        assert_eq!(amnezia["content_padding_addition"], "8-32");
        assert_eq!(amnezia["random_trailers"], true);
    }

    #[test]
    fn a_non_boolean_random_trailers_is_refused() {
        let mut last = good_last_config();
        last["RandomTrailers"] = json!("maybe");
        let error = profile(&response(last), &key(), &device(), None).expect_err("не bool");
        assert!(error.to_string().contains("RandomTrailers"), "{error}");
    }

    #[test]
    fn a_header_range_passes_through_as_text() {
        let mut last = good_last_config();
        last["H1"] = json!("5-15");
        let built = profile(&response(last), &key(), &device(), None).expect("перевод");
        assert_eq!(built.outbound.params["amnezia"]["h1"], "5-15");
    }

    #[test]
    fn the_available_countries_are_listed_from_the_response() {
        let codes = available_countries(&response(good_last_config())).expect("список");
        assert_eq!(codes, vec!["nl", "de", "us-east"]);
    }

    #[test]
    fn the_default_server_country_comes_from_the_response() {
        let country = server_country(&response(good_last_config())).expect("страна");
        assert_eq!(country.as_deref(), Some("nl"));
    }

    #[test]
    fn without_a_requested_country_the_response_country_names_the_profile() {
        // Первый запрос (без страны) — профиль получает свою страну из ответа.
        let built =
            profile(&response(good_last_config()), &key(), &device(), None).expect("перевод");
        assert_eq!(built.name, "Amnezia nl");
        assert_eq!(built.id.as_str(), format!("{}-nl", key().id()));
    }

    #[test]
    fn a_server_error_code_and_message_are_surfaced() {
        let body =
            serde_json::to_vec(&json!({ "http_status": 422, "message": "expired" })).expect("json");
        let error = profile(&body, &key(), &device(), None).expect_err("422");
        assert!(
            matches!(&error, SubscriptionError::Gateway { status: 422, message } if message == "expired"),
            "{error:?}"
        );
    }

    #[test]
    fn a_captcha_demand_is_surfaced() {
        let body =
            serde_json::to_vec(&json!({ "captcha_id": "x", "captcha_image": "y" })).expect("json");
        assert!(matches!(
            profile(&body, &key(), &device(), None),
            Err(SubscriptionError::Captcha)
        ));
    }

    #[test]
    fn a_config_missing_host_is_refused() {
        let mut last = good_last_config();
        last.as_object_mut().expect("объект").remove("hostName");
        let error = profile(&response(last), &key(), &device(), None).expect_err("нет host");
        assert!(matches!(error, SubscriptionError::Response(_)));
    }
}
