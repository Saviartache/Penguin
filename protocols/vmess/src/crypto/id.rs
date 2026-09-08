//! `cmdKey` и вывод UUID из произвольного текста.
//!
//! `penguin_core::uuid` разбирает канонический UUID и его частые записи, но
//! не превращает в UUID что попало — это MD5-преобразование нужно ровно
//! одному протоколу и не относится к общему типу (см. документ
//! [`penguin_core::uuid`]). Оно живёт здесь.

use md5::Digest as _;
use penguin_core::uuid::Uuid;

/// Магическая строка, которой дополняется UUID перед вычислением `cmdKey`.
///
/// `common/protocol/id.go`, `NewID` (эталон `v2fly/v2ray-core`, `master`):
/// `cmdKey = MD5(uuid.Bytes() || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`.
const CMD_KEY_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// Выводит `cmdKey` — ключ, из которого дальше выводится всё остальное:
/// опознаватель заголовка и оба AEAD-ключа заголовка.
pub fn cmd_key(uuid: &Uuid) -> [u8; 16] {
    let mut hasher = md5::Md5::new();
    hasher.update(uuid.as_bytes());
    hasher.update(CMD_KEY_MAGIC);
    hasher.finalize().into()
}

/// Приводит текст поля «id» к UUID.
///
/// Канонический UUID и его частые записи разбираются как обычно. Текст,
/// который UUID не является, — например, ссылка от провайдера, где вместо
/// него вписан произвольный пароль, — сворачивается в шестнадцать байт
/// через MD5, тем же способом, каким это делают клиенты семейства v2ray при
/// импорте `vmess://`: `id.rs` документа [`penguin_core::uuid`] называет этот
/// приём и оставляет его этому крейту.
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
