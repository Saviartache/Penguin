//! Опознание: токен в `authorization` и ответ сервера в `pingwin-proof`.
//!
//! ```text
//!  authorization  Pingwin b64(эфемерный клиента ‖ user ‖ client)   72 байта
//!  pingwin-proof  b64(server)                                       32 байта
//! ```
//!
//! Обе стороны здесь — чистые функции над экспортом TLS: экспорт снимает с
//! соединения тот, у кого оно есть, и приносит сюда.

use crate::error::PingwinResult;
use crate::wire::keys::{self, KEY_LEN, PUBLIC_LEN, Proofs, StaticKeyPair, USER_LEN};

/// Схема в `authorization`.
pub const SCHEME: &str = "Pingwin";

/// Заголовок ответа с доказательством сервера.
pub const PROOF_HEADER: &str = "pingwin-proof";

/// Код ответа на прошедшее опознание.
pub const ACCEPTED: u16 = 204;

/// Путь запроса опознания.
pub const PATH: &str = "/";

/// Длина токена до кодирования.
const TOKEN_LEN: usize = PUBLIC_LEN + USER_LEN + KEY_LEN;

/// Что клиент шлёт и чего ждёт в ответ.
pub struct ClientAuth {
    /// Значение `authorization`.
    pub header: String,
    /// Каким обязан прийти `pingwin-proof`.
    pub expected: [u8; KEY_LEN],
}

impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuth").finish_non_exhaustive()
    }
}

impl ClientAuth {
    /// Собирает токен для соединения с экспортом `exporter`.
    pub fn new(
        exporter: &[u8; KEY_LEN],
        server_public: &[u8; PUBLIC_LEN],
        password: &[u8],
    ) -> PingwinResult<Self> {
        let ephemeral = StaticKeyPair::generate();
        let proofs = Proofs::derive(exporter, &ephemeral.agree(server_public), password)?;
        let user = keys::user_tag(password, server_public)?;

        let mut token = Vec::with_capacity(TOKEN_LEN);
        token.extend_from_slice(&ephemeral.public);
        token.extend_from_slice(&user);
        token.extend_from_slice(&proofs.client);
        Ok(Self {
            header: format!("{SCHEME} {}", penguin_core::base64::encode_url(&token)),
            expected: proofs.server,
        })
    }

    /// Сервер ответил своим доказательством.
    pub fn accepts(&self, status: u16, proof: Option<&str>) -> bool {
        status == ACCEPTED
            && proof
                .and_then(|text| penguin_core::base64::decode(text).ok())
                .is_some_and(|bytes| keys::equal(&bytes, &self.expected))
    }
}

/// Опознанный клиент.
pub struct Admitted<'a> {
    /// Метка пользователя.
    pub user: [u8; USER_LEN],
    /// Пароль, которым он опознан.
    pub password: &'a [u8],
    /// Значение `pingwin-proof`.
    pub proof: String,
}

impl std::fmt::Debug for Admitted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admitted").finish_non_exhaustive()
    }
}

/// Проверяет `authorization`. `None` — клиент чужой, по какой бы причине.
///
/// `password` находит пароль по метке пользователя.
pub fn verify<'a>(
    header: &str,
    exporter: &[u8; KEY_LEN],
    keys: &StaticKeyPair,
    password: impl FnOnce(&[u8; USER_LEN]) -> Option<&'a [u8]>,
) -> Option<Admitted<'a>> {
    let (scheme, token) = header.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case(SCHEME) {
        return None;
    }
    let token = penguin_core::base64::decode(token).ok()?;
    if token.len() != TOKEN_LEN {
        return None;
    }
    let (ephemeral, rest) = token.split_first_chunk::<PUBLIC_LEN>()?;
    let (user, proof) = rest.split_first_chunk::<USER_LEN>()?;

    let password = password(user)?;
    let proofs = Proofs::derive(exporter, &keys.agree(ephemeral), password).ok()?;
    if !keys::equal(proof, &proofs.client) {
        return None;
    }
    Some(Admitted {
        user: *user,
        password,
        proof: penguin_core::base64::encode_url(&proofs.server),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPORTER: [u8; KEY_LEN] = [5; KEY_LEN];

    fn verified<'a>(
        auth: &ClientAuth,
        exporter: &[u8; KEY_LEN],
        server: &StaticKeyPair,
        password: &'a [u8],
    ) -> Option<Admitted<'a>> {
        let user = keys::user_tag(password, &server.public).expect("метка");
        verify(&auth.header, exporter, server, |tag| {
            (*tag == user).then_some(password)
        })
    }

    #[test]
    fn both_sides_agree() {
        let server = StaticKeyPair::generate();
        let auth = ClientAuth::new(&EXPORTER, &server.public, b"secret").expect("токен");
        assert!(auth.header.starts_with("Pingwin "));

        let admitted = verified(&auth, &EXPORTER, &server, b"secret").expect("опознан");
        assert!(auth.accepts(ACCEPTED, Some(&admitted.proof)));
    }

    #[test]
    fn a_wrong_password_is_foreign() {
        let server = StaticKeyPair::generate();
        let auth = ClientAuth::new(&EXPORTER, &server.public, b"secret").expect("токен");
        let user = keys::user_tag(b"secret", &server.public).expect("метка");
        // Метка та же, пароль на сервере другой.
        let found = verify(&auth.header, &EXPORTER, &server, |tag| {
            (*tag == user).then_some(&b"other"[..])
        });
        assert!(found.is_none());
    }

    #[test]
    fn a_token_from_another_connection_is_foreign() {
        // Повтор: экспорт TLS у нового соединения другой.
        let server = StaticKeyPair::generate();
        let auth = ClientAuth::new(&EXPORTER, &server.public, b"secret").expect("токен");
        assert!(verified(&auth, &[6; KEY_LEN], &server, b"secret").is_none());
    }

    #[test]
    fn a_server_with_another_key_is_not_accepted() {
        let real = StaticKeyPair::generate();
        let auth = ClientAuth::new(&EXPORTER, &real.public, b"secret").expect("токен");
        let other = StaticKeyPair::generate();
        assert!(verified(&auth, &EXPORTER, &other, b"secret").is_none());
    }

    #[test]
    fn the_client_wants_the_status_and_the_exact_proof() {
        let server = StaticKeyPair::generate();
        let auth = ClientAuth::new(&EXPORTER, &server.public, b"secret").expect("токен");
        let admitted = verified(&auth, &EXPORTER, &server, b"secret").expect("опознан");

        assert!(
            !auth.accepts(200, Some(&admitted.proof)),
            "сайт ответил 200"
        );
        assert!(!auth.accepts(ACCEPTED, None));
        assert!(!auth.accepts(ACCEPTED, Some("AAAA")));
    }

    #[test]
    fn garbage_is_foreign() {
        let server = StaticKeyPair::generate();
        for header in [
            "",
            "Basic dXNlcg==",
            "Pingwin",
            "Pingwin не-base64",
            "Pingwin AAAA",
        ] {
            assert!(
                verify(header, &EXPORTER, &server, |_| Some(&b"x"[..])).is_none(),
                "{header}"
            );
        }
    }
}
