//! Устройство подписки: `installation_uuid` и пара ключей WireGuard клиента.
//!
//! Держится постоянным между обновлениями (хранится файлом-спутником у
//! настроек), иначе каждый новый `public_key` тратит слот устройства
//! (`max_device_count`) на стороне Amnezia.

use penguin_core::base64;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{SubscriptionError, SubscriptionResult};

/// Постоянные данные устройства подписки.
#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    /// Идентификатор установки, как его ждёт шлюз (`installation_uuid`).
    pub installation_uuid: String,
    /// Приватный ключ WireGuard клиента, base64.
    private_key: String,
    /// Открытый ключ WireGuard клиента, base64 (едет шлюзу).
    public_key: String,
}

impl Device {
    /// Заводит новое устройство: случайный UUID и свежая пара ключей.
    pub fn generate() -> SubscriptionResult<Self> {
        let mut secret_bytes = [0u8; 32];
        getrandom::fill(&mut secret_bytes).map_err(|e| SubscriptionError::Key(e.to_string()))?;
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);

        Ok(Self {
            installation_uuid: random_uuid()?,
            private_key: base64::encode(&secret.to_bytes()),
            public_key: base64::encode(public.as_bytes()),
        })
    }

    /// Открытый ключ клиента — он едет шлюзу в поле `public_key`.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Приватный ключ клиента — им подставляется `$WIREGUARD_CLIENT_PRIVATE_KEY`.
    pub fn private_key(&self) -> &str {
        &self.private_key
    }
}

// Ключи скрыты (`AGENTS.md` §5.2).
impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("installation_uuid", &self.installation_uuid)
            .field("private_key", &"<скрыт>")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Случайный UUID версии 4 в каноническом виде `8-4-4-4-12`.
pub(crate) fn random_uuid() -> SubscriptionResult<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| SubscriptionError::Key(e.to_string()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // версия 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // вариант RFC 4122
    let h = |slice: &[u8]| slice.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        h(&bytes[0..4]),
        h(&bytes[4..6]),
        h(&bytes[6..8]),
        h(&bytes[8..10]),
        h(&bytes[10..16]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_device_has_a_uuid_and_a_valid_key_pair() {
        let device = Device::generate().expect("устройство");
        assert_eq!(device.installation_uuid.len(), 36);
        assert_eq!(device.installation_uuid.as_bytes()[14], b'4', "версия UUID");
        assert_eq!(
            base64::decode(device.private_key()).expect("ключ").len(),
            32
        );
        assert_eq!(base64::decode(device.public_key()).expect("ключ").len(), 32);
    }

    #[test]
    fn two_devices_differ() {
        let a = Device::generate().expect("a");
        let b = Device::generate().expect("b");
        assert_ne!(a.installation_uuid, b.installation_uuid);
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn a_device_survives_a_json_round_trip() {
        let device = Device::generate().expect("устройство");
        let json = serde_json::to_string(&device).expect("json");
        let back: Device = serde_json::from_str(&json).expect("разбор");
        assert_eq!(back.installation_uuid, device.installation_uuid);
        assert_eq!(back.public_key(), device.public_key());
        assert_eq!(back.private_key(), device.private_key());
    }

    #[test]
    fn neither_key_shows_up_in_debug() {
        let device = Device::generate().expect("устройство");
        let shown = format!("{device:?}");
        assert!(!shown.contains(device.private_key()), "{shown}");
    }
}
