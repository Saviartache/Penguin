//! Обращение к шлюзу: POST конверта, расшифровка ответа (фича `net`).
//!
//! Без обхода блокировок из libagw (S3-списки прокси, здоровье узлов): это
//! другой слой устойчивости, не нужный, чтобы просто забрать конфиг.

use std::time::Duration;

use serde_json::Value;
use ureq::Agent;

use crate::Options;
use crate::device::random_uuid;
use crate::envelope;
use crate::error::{SubscriptionError, SubscriptionResult};

/// Ответ шлюза крупнее не бывает; крупнее — что-то не то.
const RESPONSE_LIMIT: u64 = 1024 * 1024;

/// Срок запроса: шлюз отвечает быстро, вечно ждать незачем.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Шлёт `v1/config` и возвращает расшифрованное тело ответа.
///
/// И успех, и ошибка API приходят зашифрованными тем же ключом и с HTTP-кодом
/// ошибки, поэтому тело читается при любом коде. Открытый `{http_status,message}`
/// бывает лишь когда шлюз не смог расшифровать конверт (неверный ключ шлюза).
pub(crate) fn post_config(options: &Options<'_>, payload: &Value) -> SubscriptionResult<Vec<u8>> {
    let payload_bytes =
        serde_json::to_vec(payload).map_err(|e| SubscriptionError::Envelope(e.to_string()))?;
    let envelope = envelope::seal(&payload_bytes, options.gateway_public_key)?;

    let raw = send(&join(options.endpoint, "v1/config"), &envelope.body)?;
    if let Ok(plain) = envelope.open(&raw) {
        return Ok(plain);
    }
    // Не расшифровалось — открытая ошибка шлюза либо мусор.
    Err(plaintext_error(&raw))
}

/// Открытая ошибка шлюза `{http_status,message}`, иначе — «не расшифровано».
fn plaintext_error(raw: &[u8]) -> SubscriptionError {
    serde_json::from_slice::<Value>(raw)
        .ok()
        .and_then(|value| {
            let status = value.get("http_status").and_then(Value::as_i64)?;
            Some(SubscriptionError::Gateway {
                status,
                message: value
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            })
        })
        .unwrap_or(SubscriptionError::Decrypt)
}

/// POST тела на узел, чтение сырого ответа при любом HTTP-коде.
fn send(url: &str, body: &[u8]) -> SubscriptionResult<Vec<u8>> {
    let request_id = random_uuid()?;
    let mut response = agent()
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Client-Request-ID", request_id)
        .send(body)
        .map_err(|e| SubscriptionError::Http(format!("{url}: {e}")))?;

    response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT)
        .read_to_vec()
        .map_err(|e| SubscriptionError::Http(e.to_string()))
}

fn agent() -> Agent {
    Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        // Тело ошибки шлюза несёт `http_status`, читать его — наша забота.
        .http_status_as_error(false)
        .user_agent(concat!("penguin/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// Склеивает адрес шлюза и путь, не задваивая `/`.
fn join(endpoint: &str, path: &str) -> String {
    format!("{}/{}", endpoint.trim_end_matches('/'), path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plaintext_gateway_error_is_surfaced_with_its_message() {
        let raw = br#"{"http_status":500,"message":"internal server error"}"#;
        assert!(
            matches!(plaintext_error(raw), SubscriptionError::Gateway { status: 500, message } if message == "internal server error")
        );
    }

    #[test]
    fn undecodable_garbage_reads_as_a_decrypt_failure() {
        assert!(matches!(
            plaintext_error(&[0xff, 0x00, 0x12]),
            SubscriptionError::Decrypt
        ));
    }

    #[test]
    fn the_path_is_joined_with_a_single_slash() {
        assert_eq!(
            join("http://gw.amnezia.org:80/", "v1/config"),
            "http://gw.amnezia.org:80/v1/config"
        );
        assert_eq!(join("http://x", "v1/config"), "http://x/v1/config");
    }
}
