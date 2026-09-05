//! Пароль в заголовке `Proxy-Authorization` (RFC 7617).
//!
//! Тот же способ, что и у обычного `CONNECT`-прокси: `имя:пароль` в base64.
//! NaiveProxy изначально задуман как обвязка над Caddy, который и раздаёт
//! эту аутентификацию, — отдельного своего протокола входа у него нет.
//!
//! Кодировщик не свой: он уже есть в [`penguin_core::base64`], и заводить
//! вторую таблицу из 64 знаков в соседнем крейте незачем.

use penguin_core::base64;

/// Значение заголовка `Proxy-Authorization` целиком.
pub fn header_value(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64::encode(format!("{username}:{password}").as_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_classic_example_from_the_rfc() {
        // `Aladdin:open sesame` из RFC 7617.
        assert_eq!(
            header_value("Aladdin", "open sesame"),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn a_password_with_non_ascii_survives() {
        // Пароль на русском встречается; кодируется он байтами UTF-8, а не
        // знаками, и обрезать его нельзя.
        let value = header_value("пользователь", "пароль");
        assert!(value.starts_with("Basic "));
        assert!(value.len() > "Basic ".len());
    }
}
