//! Разбор ключа подписки `vpn://…` и сборка тела запроса `v1/config`.
//!
//! Ключ — это base64url (без хвостовых `=`), иногда поверх `qCompress` (zlib с
//! 4-байтовым префиксом длины), под которым JSON премиум-конфигурации Amnezia с
//! `api_config` и `auth_data`.

use flate2::read::ZlibDecoder;
use penguin_core::base64;
use serde_json::{Value, json};
use std::io::Read;

use crate::device::Device;
use crate::error::{SubscriptionError, SubscriptionResult};

/// Протокол, который умеет Penguin из подписки.
const SERVICE_PROTOCOL_AWG: &str = "awg";

/// Разобранный ключ подписки: всё, что нужно для запроса за серверами.
#[derive(Debug, Clone)]
pub struct SubscriptionKey {
    auth_data: Value,
    service_type: String,
    service_protocol: String,
    user_country_code: String,
    server_countries: Vec<String>,
    id: String,
}

impl SubscriptionKey {
    /// Разбирает ключ `vpn://…`.
    ///
    /// Ошибка, если протокол подписки не `awg`: другие (`vless`) Penguin из
    /// подписки не заводит.
    pub fn parse(vpn_key: &str) -> SubscriptionResult<Self> {
        let bytes = decode_blob(vpn_key)?;
        let root: Value = serde_json::from_slice(&bytes)
            .map_err(|e| SubscriptionError::Key(format!("не JSON: {e}")))?;

        let api_config = root.get("api_config").cloned().unwrap_or(Value::Null);
        let auth_data = root.get("auth_data").cloned().unwrap_or(Value::Null);

        let service_protocol = string_field(&api_config, "service_protocol");
        if service_protocol != SERVICE_PROTOCOL_AWG {
            return Err(SubscriptionError::Unsupported(format!(
                "протокол подписки `{service_protocol}` не поддержан (нужен `awg`)"
            )));
        }

        let server_countries = api_config
            .get("available_countries")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        let code = string_field(item, "server_country_code");
                        (!code.is_empty()).then_some(code)
                    })
                    .collect()
            })
            .unwrap_or_default();

        let id = subscription_id(&auth_data);

        Ok(Self {
            auth_data,
            service_type: string_field(&api_config, "service_type"),
            service_protocol,
            user_country_code: string_field(&api_config, "user_country_code"),
            server_countries,
            id,
        })
    }

    /// Устойчивая метка источника для `Profile::subscription`.
    ///
    /// Из `auth_data`, одно-направленной свёрткой — секрета не раскрывает.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Страны, под которые запрашивать серверы.
    ///
    /// Пусто в ключе — один запрос за сервером по умолчанию (`None`).
    pub fn server_countries(&self) -> Vec<Option<String>> {
        if self.server_countries.is_empty() {
            vec![None]
        } else {
            self.server_countries.iter().cloned().map(Some).collect()
        }
    }

    /// Собирает тело запроса `v1/config`.
    ///
    /// `connect_event` помечает запрос событием подключения (`is_connect_event`):
    /// шлюз держит пир устройства живым (см. [`crate::Options::connect_event`]).
    pub fn config_payload(
        &self,
        device: &Device,
        server_country: Option<&str>,
        connect_event: bool,
    ) -> Value {
        let mut payload = json!({
            "os_version": std::env::consts::OS,
            // Версия клиента Amnezia, не Penguin: шлюз требует не ниже минимума.
            "app_version": crate::GATEWAY_CLIENT_VERSION,
            "cli_name": "penguin",
            "installation_uuid": device.installation_uuid,
            "service_type": self.service_type,
            "service_protocol": self.service_protocol,
            "public_key": device.public_key(),
            "user_country_code": self.user_country_code,
            "auth_data": self.auth_data,
        });
        if let Some(country) = server_country.filter(|code| !code.is_empty()) {
            payload["server_country_code"] = json!(country);
        }
        // Поле добавляется только истинным — как у эталона.
        if connect_event {
            payload["is_connect_event"] = json!(true);
        }
        payload
    }
}

/// Снимает `vpn://`, разбирает base64url и, если под ним `qCompress`, распаковывает.
pub(crate) fn decode_blob(text: &str) -> SubscriptionResult<Vec<u8>> {
    let trimmed = text.trim();
    let body = trimmed.strip_prefix("vpn://").unwrap_or(trimmed);
    let raw = base64::decode(body).map_err(|e| SubscriptionError::Key(e.to_string()))?;
    Ok(qt_uncompress(&raw).unwrap_or(raw))
}

/// Распаковывает `qCompress` (4 байта длины + поток zlib). `None` — не сжато.
fn qt_uncompress(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() <= 4 {
        return None;
    }
    let mut out = Vec::new();
    ZlibDecoder::new(&data[4..]).read_to_end(&mut out).ok()?;
    (!out.is_empty()).then_some(out)
}

/// Строковое поле объекта, иначе пусто.
fn string_field(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Свёртка FNV-1a (не криптографическая) ключа API в короткую метку.
fn subscription_id(auth_data: &Value) -> String {
    let api_key = string_field(auth_data, "api_key");
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in api_key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("amnezia-{:016x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    /// Кодирует как ключ `vpn://`: JSON → (необязательно qCompress) → base64url.
    fn make_key(json: &Value, compress: bool) -> String {
        let plain = serde_json::to_vec(json).expect("json");
        let bytes = if compress { qt_compress(&plain) } else { plain };
        format!("vpn://{}", base64::encode_url(&bytes))
    }

    fn qt_compress(data: &[u8]) -> Vec<u8> {
        let mut out = (data.len() as u32).to_be_bytes().to_vec();
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("сжатие");
        out.extend(encoder.finish().expect("сжатие"));
        out
    }

    fn sample() -> Value {
        json!({
            "api_config": {
                "service_type": "amnezia-premium",
                "service_protocol": "awg",
                "user_country_code": "RU",
                "available_countries": [
                    { "server_country_code": "NL" },
                    { "server_country_code": "DE" }
                ]
            },
            "auth_data": { "api_key": "secret-token" }
        })
    }

    #[test]
    fn a_plain_key_parses() {
        let key = SubscriptionKey::parse(&make_key(&sample(), false)).expect("разбор");
        assert_eq!(key.service_type, "amnezia-premium");
        assert_eq!(key.user_country_code, "RU");
        assert_eq!(
            key.server_countries(),
            vec![Some("NL".to_owned()), Some("DE".to_owned())]
        );
    }

    #[test]
    fn a_compressed_key_parses_the_same() {
        let key = SubscriptionKey::parse(&make_key(&sample(), true)).expect("разбор");
        assert_eq!(key.service_type, "amnezia-premium");
        assert_eq!(key.server_countries().len(), 2);
    }

    #[test]
    fn a_key_without_countries_asks_once() {
        let mut value = sample();
        value["api_config"]["available_countries"] = json!([]);
        let key = SubscriptionKey::parse(&make_key(&value, false)).expect("разбор");
        assert_eq!(key.server_countries(), vec![None]);
    }

    #[test]
    fn a_non_awg_subscription_is_refused() {
        let mut value = sample();
        value["api_config"]["service_protocol"] = json!("vless");
        assert!(matches!(
            SubscriptionKey::parse(&make_key(&value, false)),
            Err(SubscriptionError::Unsupported(_))
        ));
    }

    #[test]
    fn garbage_is_refused() {
        assert!(SubscriptionKey::parse("vpn://не-base64-?").is_err());
        assert!(SubscriptionKey::parse("vpn://").is_err());
    }

    #[test]
    fn the_payload_carries_identity_and_auth() {
        let key = SubscriptionKey::parse(&make_key(&sample(), false)).expect("разбор");
        let device = Device::generate().expect("устройство");
        let payload = key.config_payload(&device, Some("NL"), false);

        assert_eq!(payload["service_protocol"], "awg");
        assert_eq!(payload["public_key"], device.public_key());
        assert_eq!(payload["installation_uuid"], device.installation_uuid);
        assert_eq!(payload["server_country_code"], "NL");
        assert_eq!(payload["auth_data"]["api_key"], "secret-token");
        assert_eq!(payload["cli_name"], "penguin");
        assert!(
            payload.get("is_connect_event").is_none(),
            "не событие подключения"
        );
    }

    #[test]
    fn no_country_leaves_the_field_out() {
        let key = SubscriptionKey::parse(&make_key(&sample(), false)).expect("разбор");
        let device = Device::generate().expect("устройство");
        let payload = key.config_payload(&device, None, false);
        assert!(payload.get("server_country_code").is_none());
    }

    #[test]
    fn a_connect_event_is_marked() {
        let key = SubscriptionKey::parse(&make_key(&sample(), false)).expect("разбор");
        let device = Device::generate().expect("устройство");
        let payload = key.config_payload(&device, Some("NL"), true);
        assert_eq!(payload["is_connect_event"], true);
    }

    #[test]
    fn the_id_is_stable_and_hides_the_token() {
        let key = SubscriptionKey::parse(&make_key(&sample(), false)).expect("разбор");
        let again = SubscriptionKey::parse(&make_key(&sample(), false)).expect("разбор");
        assert_eq!(key.id(), again.id());
        assert!(key.id().starts_with("amnezia-"));
        assert!(!key.id().contains("secret-token"));
    }
}
