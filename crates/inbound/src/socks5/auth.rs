//! Аутентификация по логину и паролю.
//!
//! RFC 1929:
//!
//! ```text
//! клиент → 0x01 ULEN UNAME PLEN PASSWD
//! сервер → 0x01 STATUS      (0x00 — пустили)
//! ```
//!
//! Пароль идёт открытым текстом. Это не недосмотр реализации, а свойство
//! протокола, и поэтому прокси с паролем имеет смысл только на петле:
//! проверка отсекает соседние процессы, но не того, кто видит трафик. Отказ
//! слушать чужие адреса без пароля живёт в `penguin-config::validate`.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{InboundError, InboundResult};

/// Версия подпротокола проверки.
pub const VERSION: u8 = 0x01;

/// Пустили.
const STATUS_OK: u8 = 0x00;
/// Не пустили.
const STATUS_FAILED: u8 = 0x01;

/// Логин и пароль, которые принимает точка входа.
#[derive(Clone)]
pub struct Credentials {
    /// Имя пользователя.
    pub username: String,
    /// Пароль.
    pub password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<скрыт>")
            .finish()
    }
}

/// Проверяет логин и пароль.
pub async fn verify<S>(stream: &mut S, expected: &Credentials) -> InboundResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let version = stream.read_u8().await?;
    if version != VERSION {
        return Err(InboundError::NotSocks5(version));
    }

    let username = read_field(stream).await?;
    let password = read_field(stream).await?;

    // Сравнение постоянного времени: разница между «неверное имя» и
    // «неверный пароль», выраженная временем ответа, — это подсказка тому,
    // кто перебирает.
    let ok = constant_time_eq(username.as_bytes(), expected.username.as_bytes())
        & constant_time_eq(password.as_bytes(), expected.password.as_bytes());

    let status = if ok { STATUS_OK } else { STATUS_FAILED };
    stream.write_all(&[VERSION, status]).await?;

    if ok {
        Ok(())
    } else {
        Err(InboundError::AuthFailed)
    }
}

/// Читает поле «длина плюс байты».
async fn read_field<S>(stream: &mut S) -> InboundResult<String>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let len = stream.read_u8().await? as usize;
    let mut bytes = vec![0u8; len];
    stream.read_exact(&mut bytes).await?;
    String::from_utf8(bytes).map_err(|_| InboundError::AuthFailed)
}

/// Сравнение, не завершающееся на первом различии.
///
/// Разная длина различается сразу — её и так видно по трафику.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    fn credentials() -> Credentials {
        Credentials {
            username: "user".to_owned(),
            password: "secret".to_owned(),
        }
    }

    fn request(username: &str, password: &str) -> Vec<u8> {
        let mut out = vec![VERSION, username.len() as u8];
        out.extend_from_slice(username.as_bytes());
        out.push(password.len() as u8);
        out.extend_from_slice(password.as_bytes());
        out
    }

    async fn run(bytes: &[u8]) -> (InboundResult<()>, Vec<u8>) {
        let (mut ours, mut theirs) = duplex(1024);
        theirs.write_all(bytes).await.expect("запись");
        let result = verify(&mut ours, &credentials()).await;
        let mut reply = vec![0u8; 2];
        let _ = theirs.read_exact(&mut reply).await;
        (result, reply)
    }

    #[tokio::test]
    async fn accepts_correct_credentials() {
        let (result, reply) = run(&request("user", "secret")).await;
        result.expect("пустили");
        assert_eq!(reply, vec![VERSION, STATUS_OK]);
    }

    #[tokio::test]
    async fn rejects_wrong_password() {
        let (result, reply) = run(&request("user", "wrong")).await;
        assert!(matches!(result, Err(InboundError::AuthFailed)));
        assert_eq!(reply, vec![VERSION, STATUS_FAILED]);
    }

    #[tokio::test]
    async fn rejects_wrong_username() {
        let (result, _) = run(&request("someone", "secret")).await;
        assert!(matches!(result, Err(InboundError::AuthFailed)));
    }

    #[test]
    fn comparison_is_length_safe() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn debug_hides_the_password() {
        let rendered = format!("{:?}", credentials());
        assert!(!rendered.contains("secret"), "пароль в Debug: {rendered}");
    }
}
