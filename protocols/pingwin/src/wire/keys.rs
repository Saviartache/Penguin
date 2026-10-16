//! Ключи опознания: из X25519, экспорта TLS и пароля — в два доказательства.
//!
//! ```text
//!  ss      = X25519(эфемерный клиента, постоянный сервера)
//!  user    = Expand(Extract(постоянный сервера, пароль), "pingwin user", 8)
//!  prk     = Extract(exporter, ss ‖ пароль)
//!  client  = Expand(prk, "pingwin client", 32)
//!  server  = Expand(prk, "pingwin server", 32)
//! ```
//!
//! # Что даёт каждая часть
//!
//! **`ss`** посчитает только владелец закрытого ключа сервера: сервер с
//! чужим ключом, даже с верным сертификатом, не выдаст `server` и не проверит
//! `client`, а значит, и пароль по нему не переберёт.
//!
//! **`exporter`** — экспорт ключей TLS этого соединения (RFC 8446, §7.5). Он
//! свой у каждого соединения, и токен, снятый с одного, на другом не пройдёт:
//! окна повторов не нужно.
//!
//! **Пароль** отличает пользователей одного сервера друг от друга.

use ring::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{PingwinError, PingwinResult};

/// Длина ключа и любого выведенного секрета.
pub const KEY_LEN: usize = 32;

/// Длина открытого ключа X25519.
pub const PUBLIC_LEN: usize = 32;

/// Длина метки пользователя.
pub const USER_LEN: usize = 8;

/// Метка экспорта TLS. Длина экспорта — [`KEY_LEN`], контекст пустой.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-pingwin";

/// Метка во всех выводах ключей.
const LABEL: &str = "pingwin";

/// Постоянная пара ключей сервера; у клиента — эфемерная.
///
/// Тип многоразовый (`StaticSecret`) намеренно: у сервера секрет участвует в
/// согласовании на каждом соединении, а `ring::agreement` тратит ключ первым
/// же вызовом.
pub struct StaticKeyPair {
    secret: StaticSecret,
    /// Открытая половина — то, что стоит в профиле клиента.
    pub public: [u8; PUBLIC_LEN],
}

impl std::fmt::Debug for StaticKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticKeyPair").finish_non_exhaustive()
    }
}

impl StaticKeyPair {
    /// Новая пара.
    pub fn generate() -> Self {
        Self::from_secret(StaticSecret::random())
    }

    /// Пара из закрытой половины.
    pub fn from_bytes(secret: [u8; KEY_LEN]) -> Self {
        Self::from_secret(StaticSecret::from(secret))
    }

    fn from_secret(secret: StaticSecret) -> Self {
        let public = *PublicKey::from(&secret).as_bytes();
        Self { secret, public }
    }

    /// Закрытая половина — только затем, чтобы её записать в файл настроек.
    pub fn secret_bytes(&self) -> [u8; KEY_LEN] {
        self.secret.to_bytes()
    }

    /// Общий секрет с открытым ключом собеседника.
    pub fn agree(&self, peer: &[u8; PUBLIC_LEN]) -> [u8; KEY_LEN] {
        *self
            .secret
            .diffie_hellman(&PublicKey::from(*peer))
            .as_bytes()
    }
}

/// Доказательства обеих сторон для одного соединения.
pub struct Proofs {
    /// Что предъявляет клиент.
    pub client: [u8; KEY_LEN],
    /// Что предъявляет сервер.
    pub server: [u8; KEY_LEN],
}

impl std::fmt::Debug for Proofs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ни целиком, ни первыми байтами (`AGENTS.md` §5.2).
        f.debug_struct("Proofs").finish_non_exhaustive()
    }
}

impl Proofs {
    /// Выводит доказательства из экспорта TLS, общего секрета и пароля.
    pub fn derive(
        exporter: &[u8; KEY_LEN],
        shared: &[u8; KEY_LEN],
        password: &[u8],
    ) -> PingwinResult<Self> {
        let mut ikm = Vec::with_capacity(KEY_LEN + password.len());
        ikm.extend_from_slice(shared);
        ikm.extend_from_slice(password);
        let prk = Salt::new(HKDF_SHA256, exporter).extract(&ikm);
        Ok(Self {
            client: expand(&prk, "client")?,
            server: expand(&prk, "server")?,
        })
    }
}

/// Метка пользователя: восемь байт, по которым сервер находит его пароль.
///
/// Привязана к ключу сервера: один пароль на двух серверах даёт две метки.
pub fn user_tag(
    password: &[u8],
    server_public: &[u8; PUBLIC_LEN],
) -> PingwinResult<[u8; USER_LEN]> {
    let prk = Salt::new(HKDF_SHA256, server_public).extract(password);
    let mut tag = [0u8; USER_LEN];
    fill(&prk, "user", &mut tag)?;
    Ok(tag)
}

/// Сравнение за постоянное время: по времени ответа не подобрать байт.
pub fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn expand(prk: &Prk, purpose: &str) -> PingwinResult<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    fill(prk, purpose, &mut key)?;
    Ok(key)
}

/// Длина вывода. `ring` требует её типом, а не числом.
struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn fill(prk: &Prk, purpose: &str, out: &mut [u8]) -> PingwinResult<()> {
    let label = format!("{LABEL} {purpose}");
    let info = [label.as_bytes()];
    prk.expand(&info, Len(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| PingwinError::malformed("ключ не выводится"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proofs(exporter: u8, shared: u8, password: &[u8]) -> Proofs {
        Proofs::derive(&[exporter; KEY_LEN], &[shared; KEY_LEN], password).expect("выводятся")
    }

    #[test]
    fn a_static_pair_agrees_with_itself_from_both_sides() {
        let server = StaticKeyPair::generate();
        let client = StaticKeyPair::generate();
        assert_eq!(server.agree(&client.public), client.agree(&server.public));
    }

    #[test]
    fn a_pair_survives_the_trip_through_its_own_bytes() {
        let pair = StaticKeyPair::generate();
        assert_eq!(
            StaticKeyPair::from_bytes(pair.secret_bytes()).public,
            pair.public
        );
    }

    #[test]
    fn the_two_sides_never_share_a_proof() {
        // Иначе подставной сервер вернул бы клиенту его же доказательство.
        let proofs = proofs(1, 2, b"secret");
        assert_ne!(proofs.client, proofs.server);
    }

    #[test]
    fn every_input_takes_part() {
        let base = proofs(1, 2, b"secret").client;
        assert_ne!(base, proofs(9, 2, b"secret").client, "экспорт TLS");
        assert_ne!(base, proofs(1, 9, b"secret").client, "общий секрет");
        assert_ne!(base, proofs(1, 2, b"other").client, "пароль");
    }

    #[test]
    fn a_user_tag_is_bound_to_the_server_it_is_shown_to() {
        let one = user_tag(b"secret", &[1u8; 32]).expect("считается");
        assert_ne!(one, user_tag(b"secret", &[2u8; 32]).expect("считается"));
        assert_ne!(one, user_tag(b"another", &[1u8; 32]).expect("считается"));
    }

    #[test]
    fn equal_compares_whole_slices() {
        assert!(equal(b"abc", b"abc"));
        assert!(!equal(b"abc", b"abd"));
        assert!(!equal(b"abc", b"ab"));
    }

    #[test]
    fn debug_shows_no_key_material() {
        let rendered = format!("{:?}", proofs(1, 2, b"secret"));
        assert!(!rendered.contains("client"), "{rendered}");
        let pair = StaticKeyPair::generate();
        assert!(!format!("{pair:?}").contains(&format!("{:?}", pair.public)));
    }
}
