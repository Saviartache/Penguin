//! Ошибки устройства; отсутствие драйвера и нехватка прав — отдельные варианты с готовым текстом.

use thiserror::Error;

/// Результат работы с устройством.
pub type TunResult<T> = Result<T, TunError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum TunError {
    /// Драйвер не найден; в сообщении каталог, где искали (служба запускает свою копию).
    #[error(
        "не найден драйвер Wintun: положите `wintun.dll` в {0} \
         (скачать: https://www.wintun.net)"
    )]
    DriverMissing(String),

    /// Модуля `tun` нет в ядре (Linux).
    #[error("модуль ядра `tun` не загружен: `sudo modprobe tun`")]
    TunModuleMissing,

    /// Не хватает прав.
    #[error("создание адаптера требует прав администратора")]
    PermissionDenied,

    /// Адаптер не создаётся; причина — текст драйвера как есть.
    #[error("не удалось создать адаптер `{name}`: {reason}")]
    AdapterCreation {
        /// Имя адаптера.
        name: String,
        /// Что сказала система.
        reason: String,
    },

    /// Адаптер закрыт: так читающая задача видит остановку тоннеля.
    #[error("адаптер закрыт")]
    Closed,

    /// Пакет длиннее MTU.
    #[error("пакет длиной {size} байт не помещается в MTU {mtu}")]
    PacketTooLarge {
        /// Длина пакета.
        size: usize,
        /// Настроенный MTU.
        mtu: u16,
    },

    /// Платформа не поддерживается.
    #[error("режим тоннеля на этой платформе не поддерживается")]
    Unsupported,

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl TunError {
    /// Ошибка создания адаптера.
    pub fn adapter(name: impl Into<String>, source: impl std::fmt::Display) -> Self {
        Self::AdapterCreation {
            name: name.into(),
            reason: source.to_string(),
        }
    }

    /// Нужно ли пользователю что-то сделать, прежде чем повторять (по нему решает `supervisor`).
    pub fn needs_user_action(&self) -> bool {
        matches!(
            self,
            Self::DriverMissing(_)
                | Self::TunModuleMissing
                | Self::PermissionDenied
                | Self::Unsupported
        )
    }

    /// Драйвера нет там, где его искали.
    pub fn driver_missing(directory: &std::path::Path) -> Self {
        Self::DriverMissing(directory.display().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_error_tells_what_to_do() {
        let message = TunError::driver_missing(std::path::Path::new(r"C:\penguin")).to_string();
        assert!(
            message.contains("wintun.dll"),
            "не сказано, чего не хватает"
        );
        assert!(message.contains("wintun.net"), "не сказано, где взять");
        assert!(message.contains(r"C:\penguin"), "не сказано, куда класть");
    }

    #[test]
    fn user_fixable_errors_are_not_retried() {
        assert!(TunError::driver_missing(std::path::Path::new("C:/penguin")).needs_user_action());
        assert!(TunError::TunModuleMissing.needs_user_action());
        assert!(TunError::PermissionDenied.needs_user_action());
        assert!(!TunError::Closed.needs_user_action());
    }
}
