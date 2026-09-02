//! Проверка прав и понятное сообщение, если их нет.
//!
//! Самая частая причина «не работает» у VPN-клиента на Windows: TUN-адаптер,
//! маршруты и брандмауэр требуют повышенных прав, а запущен клиент от
//! обычного пользователя. Сказать об этом надо **до** попытки, а не после
//! невнятной ошибки драйвера.

/// Что клиент может делать с текущими правами.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// Права есть: тоннель доступен.
    Elevated,
    /// Прав нет: работает только режим прокси.
    Limited,
}

impl Privilege {
    /// Текущие права.
    pub fn current() -> Self {
        if is_elevated() {
            Self::Elevated
        } else {
            Self::Limited
        }
    }

    /// Тоннель доступен.
    pub fn allows_tunnel(self) -> bool {
        self == Self::Elevated
    }

    /// Что сказать пользователю.
    pub fn explain(self) -> &'static str {
        match self {
            Self::Elevated => "права повышены — доступен режим тоннеля",
            Self::Limited => {
                "обычные права: доступен режим прокси; для тоннеля запустите \
                 клиент от администратора"
            }
        }
    }
}

/// Запущены ли мы с повышенными правами.
#[cfg(windows)]
#[allow(unsafe_code, reason = "чтение токена процесса")]
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::from_mut(&mut elevation).cast()),
            u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>()).unwrap_or(0),
            &mut returned,
        )
    }
    .is_ok();

    // Дескриптор закрывается в любом случае: проверка вызывается при каждом
    // запуске тоннеля и при диагностике.
    let _ = unsafe { CloseHandle(token) };

    ok && elevation.TokenIsElevated != 0
}

/// Запущены ли мы от суперпользователя.
#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    nix::unistd::geteuid().is_root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_does_not_panic() {
        // Вызывается при каждом запуске и при диагностике; упасть здесь
        // означало бы не запуститься вовсе.
        let _ = Privilege::current();
    }

    #[test]
    fn limited_explains_what_to_do() {
        let message = Privilege::Limited.explain();
        assert!(
            message.contains("администратора"),
            "не сказано, что делать: {message}"
        );
        assert!(
            message.contains("прокси"),
            "не сказано, что всё же работает: {message}"
        );
    }

    #[test]
    fn only_elevated_allows_the_tunnel() {
        assert!(Privilege::Elevated.allows_tunnel());
        assert!(!Privilege::Limited.allows_tunnel());
    }

    #[test]
    fn repeated_checks_agree() {
        // Права в пределах процесса не меняются; расхождение означало бы
        // утечку дескриптора или порчу памяти в самой проверке.
        let first = Privilege::current();
        for _ in 0..100 {
            assert_eq!(Privilege::current(), first);
        }
    }
}
