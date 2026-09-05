//! Отпечаток хоста: в какой записи он придёт и как сверяется.
//!
//! SSH без проверки хоста — это тот же `insecure`, только молчаливый: любой,
//! кто перехватил соединение, становится «сервером». Отсюда правило — поле
//! отпечатка в настройках обязательно, и разбирать его нужно в той записи,
//! которая у человека будет на руках, а не в той, которую удобнее нам.
//!
//! Записей две, и обе приняты:
//!
//! - **Строка `ssh-keyscan`** (и она же — строка `known_hosts`): алгоритм и
//!   сам ключ в base64, например `ssh-ed25519 AAAAC3...`. Её человек получает
//!   одной командой, не запуская клиент второй раз.
//! - **Строка `ssh-keygen -l`**: свёртка SHA-256 в записи `SHA256:...`. Её
//!   печатает уже работающий клиент, и переписывать её в другую запись
//!   значило бы требовать разбора, который человеку не нужен.

use russh::keys::ssh_key::Fingerprint;
use russh::keys::{HashAlg, PublicKey, parse_public_key_base64};

use crate::error::{SshError, SshResult};

/// Ожидаемый отпечаток хоста — в той форме, в которой он был задан.
#[derive(Debug, Clone)]
pub enum HostFingerprint {
    /// Весь публичный ключ: запись `ssh-keyscan`/`known_hosts`.
    Key(PublicKey),
    /// Свёртка SHA-256: запись `ssh-keygen -l`.
    Hash(Fingerprint),
}

impl HostFingerprint {
    /// Разбирает строку из настроек.
    ///
    /// Строка `known_hosts` может нести перед ключом имя хоста и после него —
    /// комментарий; ни то, ни другое не обязано отсутствовать, и порядковое
    /// место ключа в строке заранее не известно. Поэтому base64 ищется
    /// перебором всех слов, а не по фиксированной позиции.
    pub fn parse(raw: &str) -> SshResult<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(SshError::config(
                "отпечаток хоста не задан: без него сервер подменит кто угодно",
            ));
        }

        if raw.starts_with("SHA256:") {
            return raw
                .parse::<Fingerprint>()
                .map(Self::Hash)
                .map_err(|e| SshError::config(format!("отпечаток хоста `{raw}`: {e}")));
        }

        let mut last_err = None;
        for word in raw.split_ascii_whitespace() {
            match parse_public_key_base64(word) {
                Ok(key) => return Ok(Self::Key(key)),
                Err(e) => last_err = Some(e),
            }
        }

        Err(SshError::config(format!(
            "отпечаток хоста `{raw}` не разбирается ни как ключ ssh-keyscan/known_hosts, \
             ни как SHA-256 из ssh-keygen -l: {}",
            last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "строка пуста".to_owned())
        )))
    }

    /// Сверяет ключ, который прислал сервер, с ожидаемым.
    pub fn matches(&self, presented: &PublicKey) -> bool {
        match self {
            Self::Key(expected) => presented == expected,
            Self::Hash(expected) => presented.fingerprint(HashAlg::Sha256) == *expected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Настоящие тестовые ключи из наборов ssh-key/OpenSSH: подделать такую
    // строку рукой — верный способ проверить не разбор, а свою арифметику.
    const ED25519: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti \
         user@example.com";
    const ECDSA: &str = "ecdsa-sha2-nistp256 \
         AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHwf2HMM5TRXvo2SQJjsNkiDD5Kq\
         iiNjrGVv3UUh+mMT5RHxiRtOnlqvjhQtBq0VpmpCV/PwUdhOig4vkbqAcEc= user@example.com";

    fn key(line: &str) -> PublicKey {
        match HostFingerprint::parse(line).expect("тестовый ключ разбирается")
        {
            HostFingerprint::Key(key) => key,
            HostFingerprint::Hash(_) => unreachable!("тестовые строки — не хэш"),
        }
    }

    #[test]
    fn a_known_hosts_line_is_understood() {
        // Ровно то, что печатает `ssh-keyscan`: хост, алгоритм, ключ.
        let line = format!("example.com {ED25519}");
        let fingerprint = HostFingerprint::parse(&line).expect("разбирается");
        assert!(fingerprint.matches(&key(ED25519)));
    }

    #[test]
    fn a_public_key_file_line_works_too() {
        // Та же тройка полей, но без хоста и с комментарием в конце — так
        // выглядит `id_ed25519.pub`, который тоже может оказаться под рукой.
        let fingerprint = HostFingerprint::parse(ED25519).expect("разбирается");
        assert!(fingerprint.matches(&key(ED25519)));
    }

    #[test]
    fn a_bare_base64_key_is_understood_too() {
        let base64 = ED25519
            .split_ascii_whitespace()
            .nth(1)
            .expect("среднее слово строки — ключ");
        let fingerprint = HostFingerprint::parse(base64).expect("разбирается");
        assert!(fingerprint.matches(&key(ED25519)));
    }

    #[test]
    fn a_sha256_fingerprint_is_understood() {
        // Строка, которую печатает `ssh-keygen -l` уже подключённого клиента.
        let text = key(ED25519).fingerprint(HashAlg::Sha256).to_string();
        assert!(text.starts_with("SHA256:"));
        let fingerprint = HostFingerprint::parse(&text).expect("разбирается");
        assert!(fingerprint.matches(&key(ED25519)));
    }

    #[test]
    fn a_different_key_does_not_match() {
        // Не то же самое, что ошибка разбора: обе строки — валидные ключи,
        // просто разных серверов.
        let fingerprint = HostFingerprint::parse(ED25519).expect("разбирается");
        assert!(!fingerprint.matches(&key(ECDSA)));
    }

    #[test]
    fn garbage_is_refused() {
        assert!(HostFingerprint::parse("это не отпечаток").is_err());
        assert!(HostFingerprint::parse("").is_err());
        assert!(HostFingerprint::parse("   ").is_err());
        assert!(HostFingerprint::parse("SHA256:не-то").is_err());
    }
}
