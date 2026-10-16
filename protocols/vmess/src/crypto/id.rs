//! `cmdKey` и вывод UUID из произвольного текста.

use md5::Digest as _;
use penguin_core::uuid::Uuid;

/// `cmdKey = MD5(uuid || магия)`: `common/protocol/id.go`, `NewID`, `v2fly/v2ray-core`.
const CMD_KEY_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// Ключ, из которого выводятся опознаватель и оба AEAD-ключа заголовка.
pub fn cmd_key(uuid: &Uuid) -> [u8; 16] {
    let mut hasher = md5::Md5::new();
    hasher.update(uuid.as_bytes());
    hasher.update(CMD_KEY_MAGIC);
    hasher.finalize().into()
}

/// UUID из текста; не-UUID сворачивается через MD5, как при импорте `vmess://` в клиентах v2ray.
pub fn resolve(text: &str) -> Uuid {
    if let Ok(uuid) = text.parse() {
        return uuid;
    }
    let digest = md5::Md5::digest(text.trim().as_bytes());
    Uuid::from_bytes(digest.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_canonical_uuid_parses_as_usual() {
        let text = "b831381d-6324-4d53-ad4f-8cda48b30811";
        assert_eq!(resolve(text).to_string(), text);
    }

    #[test]
    fn arbitrary_text_folds_into_sixteen_bytes() {
        let uuid = resolve("моя кодовая фраза");
        assert!(!uuid.is_nil());
    }

    #[test]
    fn the_same_text_always_folds_the_same_way() {
        assert_eq!(resolve("пароль"), resolve("пароль"));
    }

    #[test]
    fn different_text_folds_differently() {
        assert_ne!(resolve("пароль-один"), resolve("пароль-два"));
    }

    #[test]
    fn cmd_key_is_stable_for_the_same_uuid() {
        let uuid: Uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
            .parse()
            .expect("разбирается");
        assert_eq!(cmd_key(&uuid), cmd_key(&uuid));
    }
}
