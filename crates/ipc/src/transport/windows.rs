//! Именованный канал с дескриптором безопасности.
//!
//! # Почему это не формальность
//!
//! Демон работает с правами системы. Всё, что он делает по запросу из канала,
//! доступно тому, кто до канала дотянулся: выключить kill switch, переписать
//! правила маршрутизации, увести весь трафик машины в чужой сервер.
//!
//! Именованный канал, созданный без дескриптора безопасности, получает
//! умолчание — и оно щедрее, чем хотелось бы. Поэтому здесь дескриптор задан
//! явно и в понятной записи:
//!
//! ```text
//!   D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)
//!         │            │            │
//!         │            │            └─ вошедший пользователь: чтение и запись
//!         │            └─ администраторы: всё
//!         └─ система: всё
//! ```
//!
//! Вошедший пользователь получает чтение и запись, но не право менять сам
//! дескриптор: интерфейс работает под ним и должен уметь говорить с демоном,
//! но не должен уметь открыть канал кому-то ещё.

use interprocess::local_socket::ListenerOptions;
use interprocess::os::windows::local_socket::ListenerOptionsExt;
use interprocess::os::windows::security_descriptor::SecurityDescriptor;

use crate::error::{IpcError, IpcResult};

/// Дескриптор безопасности канала управления.
///
/// `SY` — система, `BA` — администраторы, `IU` — вошедший пользователь.
/// `GA` — полный доступ, `GRGW` — чтение и запись.
const CHANNEL_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// Добавляет к настройкам слушателя дескриптор безопасности.
pub fn secure(options: ListenerOptions<'_>) -> IpcResult<ListenerOptions<'_>> {
    let sddl = widestring::U16CString::from_str(CHANNEL_SDDL)
        .map_err(|e| IpcError::Transport(format!("дескриптор безопасности: {e}")))?;

    let descriptor = SecurityDescriptor::deserialize(&sddl)
        .map_err(|e| IpcError::Transport(format!("не разбирается дескриптор безопасности: {e}")))?;

    Ok(options.security_descriptor(descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_is_accepted_by_windows() {
        // Ошибка в записи означала бы канал с умолчанием — то есть более
        // щедрым доступом, чем задумано.
        let sddl = widestring::U16CString::from_str(CHANNEL_SDDL).expect("строка");
        SecurityDescriptor::deserialize(&sddl).expect("дескриптор разбирается");
    }

    #[test]
    fn descriptor_grants_the_interactive_user_only_read_write() {
        // Интерфейс работает под пользователем и должен уметь говорить с
        // демоном — но не открывать канал кому-то ещё.
        assert!(CHANNEL_SDDL.contains("(A;;GRGW;;;IU)"));
        assert!(
            !CHANNEL_SDDL.contains("(A;;GA;;;IU)"),
            "пользователю дан полный доступ"
        );
    }

    #[test]
    fn descriptor_grants_system_and_admins_full_access() {
        assert!(CHANNEL_SDDL.contains("(A;;GA;;;SY)"));
        assert!(CHANNEL_SDDL.contains("(A;;GA;;;BA)"));
    }

    #[test]
    fn descriptor_does_not_grant_everyone() {
        // `WD` — Everyone. Канал, открытый всем, означает, что любой процесс
        // может выключить kill switch.
        assert!(!CHANNEL_SDDL.contains(";;WD)"), "доступ открыт всем");
    }
}
