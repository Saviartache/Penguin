//! Linux: `resolvectl` (systemd-resolved, по интерфейсу), а без него — замена `/etc/resolv.conf`
//! с сохранением прежнего файла рядом (он переживает падение клиента).

use std::net::IpAddr;
use std::path::Path;

use crate::command;
use crate::error::{PlatformError, PlatformResult};

/// Программа `systemd-resolved`.
const RESOLVECTL: &str = "resolvectl";

/// Файл настроек резолвера.
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Куда сохраняется прежний файл.
const RESOLV_CONF_BACKUP: &str = "/etc/resolv.conf.penguin-backup";

/// Объявляет адрес единственным DNS интерфейса.
pub fn set(interface_index: u32, server: IpAddr) -> PlatformResult<()> {
    let name = interface_name(interface_index)?;

    if command::exists(RESOLVECTL) {
        command::run(RESOLVECTL, &["dns", &name, &server.to_string()])
            .map_err(|err| err.into_error(PlatformError::DnsSettings, "настройки DNS"))?;
        // `~.`: иначе имена без домена интерфейса к нашему серверу не попадут.
        command::run(RESOLVECTL, &["domain", &name, "~."])
            .map_err(|err| err.into_error(PlatformError::DnsSettings, "настройки DNS"))?;
        return Ok(());
    }

    if !Path::new(RESOLV_CONF_BACKUP).exists() {
        std::fs::copy(RESOLV_CONF, RESOLV_CONF_BACKUP)
            .map_err(|err| PlatformError::DnsSettings(format!("{RESOLV_CONF_BACKUP}: {err}")))?;
    }
    std::fs::write(RESOLV_CONF, resolv_conf(server))
        .map_err(|err| PlatformError::DnsSettings(format!("{RESOLV_CONF}: {err}")))
}

/// Возвращает настройки, какими они были.
pub fn reset(interface_index: u32) -> PlatformResult<()> {
    if command::exists(RESOLVECTL) {
        let name = interface_name(interface_index)?;
        // Адаптер мог закрыться раньше: возвращать нечего — это успех.
        if let Err(err) = command::run(RESOLVECTL, &["revert", &name]) {
            tracing::debug!(?err, "возвращать настройки резолвера было нечего");
        }
        return Ok(());
    }

    if !Path::new(RESOLV_CONF_BACKUP).exists() {
        return Ok(());
    }
    std::fs::copy(RESOLV_CONF_BACKUP, RESOLV_CONF)
        .map_err(|err| PlatformError::rollback("настройки DNS", err))?;
    std::fs::remove_file(RESOLV_CONF_BACKUP)
        .map_err(|err| PlatformError::rollback("сохранённые настройки DNS", err))?;
    Ok(())
}

/// Содержимое `/etc/resolv.conf` на время сеанса; лишний сервер в нём — утечка мимо тоннеля.
fn resolv_conf(server: IpAddr) -> String {
    format!(
        "# Файл заменён VPN-клиентом Penguin на время сеанса.\n\
         # Прежний сохранён в {RESOLV_CONF_BACKUP}.\n\
         nameserver {server}\n"
    )
}

/// Имя интерфейса по его номеру.
fn interface_name(interface_index: u32) -> PlatformResult<String> {
    let mut buffer = [0u8; 32];

    #[allow(unsafe_code, reason = "перевод номера интерфейса в имя")]
    // SAFETY: буфер не короче `IF_NAMESIZE`.
    let name = unsafe {
        libc::if_indextoname(interface_index, buffer.as_mut_ptr().cast::<libc::c_char>())
    };
    if name.is_null() {
        return Err(PlatformError::DnsSettings(format!(
            "интерфейс {interface_index} не найден"
        )));
    }

    let end = buffer.iter().position(|byte| *byte == 0).unwrap_or(0);
    Ok(String::from_utf8_lossy(&buffer[..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_names_exactly_one_server() {
        let text = resolv_conf("198.18.0.1".parse().expect("адрес"));
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("nameserver"))
                .count(),
            1,
            "{text}"
        );
        assert!(text.contains("nameserver 198.18.0.1"), "{text}");
    }

    #[test]
    fn the_file_says_where_the_original_went() {
        let text = resolv_conf("198.18.0.1".parse().expect("адрес"));
        assert!(text.contains(RESOLV_CONF_BACKUP), "{text}");
    }

    #[test]
    fn loopback_is_a_valid_interface() {
        assert!(interface_name(1).is_ok());
    }

    #[test]
    fn a_missing_interface_is_an_error_not_a_panic() {
        assert!(interface_name(u32::MAX).is_err());
    }
}
