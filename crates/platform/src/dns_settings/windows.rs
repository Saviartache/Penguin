//! Windows: DNS на интерфейсе и сброс кэша.
//!
//! Настройки меняются через `netsh`, а не через реестр: запись в реестр
//! действует только после перезапуска сетевого стека, а `netsh` применяет
//! изменение сразу. Клиенту нужно именно сразу — пользователь нажал
//! «подключить» и ждёт, что заработает.
//!
//! После смены обязателен сброс кэша резолвера. Без него система продолжает
//! отвечать старыми адресами, и первые минуты после подключения выглядят как
//! «VPN не работает».

use std::net::IpAddr;
use std::process::Command;

use crate::error::{PlatformError, PlatformResult};

/// Объявляет адрес единственным DNS интерфейса.
pub fn set(interface_index: u32, server: IpAddr) -> PlatformResult<()> {
    let family = if server.is_ipv4() { "ipv4" } else { "ipv6" };

    netsh(&[
        "interface",
        family,
        "set",
        "dnsservers",
        &format!("name={interface_index}"),
        "source=static",
        &format!("address={server}"),
        "register=none",
        "validate=no",
    ])?;

    flush_cache();
    Ok(())
}

/// Возвращает интерфейсу автоматическое получение DNS.
pub fn reset(interface_index: u32) -> PlatformResult<()> {
    let mut first_error = None;

    // Оба семейства: подменено могло быть любое, а узнать какое — дороже, чем
    // сбросить оба.
    for family in ["ipv4", "ipv6"] {
        let result = netsh(&[
            "interface",
            family,
            "set",
            "dnsservers",
            &format!("name={interface_index}"),
            "source=dhcp",
        ]);
        if let Err(err) = result {
            first_error.get_or_insert(err);
        }
    }

    flush_cache();

    match first_error {
        Some(err) => Err(PlatformError::rollback("настройки DNS", err)),
        None => Ok(()),
    }
}

/// Сбрасывает кэш резолвера.
///
/// Ошибка не считается фатальной: кэш всё равно истечёт сам, просто позже.
fn flush_cache() {
    let result = Command::new("ipconfig").arg("/flushdns").output();
    if let Err(err) = result {
        tracing::debug!(%err, "кэш DNS не сброшен");
    }
}

/// Выполняет команду настройки сети.
fn netsh(args: &[&str]) -> PlatformResult<()> {
    let output = Command::new("netsh")
        .args(args)
        .output()
        .map_err(|e| PlatformError::DnsSettings(format!("не запускается netsh: {e}")))?;

    if output.status.success() {
        return Ok(());
    }

    let message = String::from_utf8_lossy(&output.stdout);
    if message.contains("Access is denied") || message.contains("Отказано в доступе")
    {
        return Err(PlatformError::PermissionDenied("настройки DNS".to_owned()));
    }

    Err(PlatformError::DnsSettings(message.trim().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flushing_the_cache_never_fails_loudly() {
        // Кэш всё равно истечёт сам; падать из-за него на пути подключения
        // нельзя.
        flush_cache();
    }

    #[test]
    fn resetting_a_missing_interface_is_reported_not_panicking() {
        // Индекс, которого заведомо нет.
        match reset(u32::MAX - 1) {
            Ok(()) => {}
            Err(err) => assert!(
                matches!(err, PlatformError::RollbackFailed { .. }) || err.needs_privileges(),
                "неожиданная ошибка: {err}"
            ),
        }
    }
}
