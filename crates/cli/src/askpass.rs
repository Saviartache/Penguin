//! Ответ `ssh` на запрос пароля: этот же файл в роли `SSH_ASKPASS`.

/// Переменная, в которой `deploy` передаёт пароль запущенному им `ssh`.
pub const VARIABLE: &str = "PENGUIN_SSH_ASKPASS";

/// Пароль, если процесс запущен как `SSH_ASKPASS`; тогда печатать его и выйти.
pub fn reply() -> Option<String> {
    std::env::var(VARIABLE).ok()
}
