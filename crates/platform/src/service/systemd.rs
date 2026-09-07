//! Serialization of Penguin-owned systemd units, without OS calls.

use std::path::PathBuf;

use super::ServiceStatus;
use crate::error::{PlatformError, PlatformResult};

/// Где лежит копия, которую запускает systemd.
///
/// Постоянное место, принадлежащее `root`, а не тот путь, где оказался
/// запущенный файл. Юнит, указывающий в каталог сборки или на съёмный
/// носитель, systemd примет — и откажет при следующей загрузке, когда там
/// уже ничего нет. `/usr/local/lib` — место для того, что поставили не
/// пакетным менеджером и что человек не зовёт руками (FHS 3.0, §4.5).
pub(super) const HELPER_DIR: &str = "/usr/local/lib/penguin";
pub(super) const HELPER_PATH: &str = "/usr/local/lib/penguin/penguin";

/// Описание службы. Путь в нём постоянный, поэтому экранировать нечего.
pub(super) const UNIT_TEXT: &str = "[Unit]\n\
     Description=Penguin VPN\n\
     After=network.target\n\
     \n\
     [Service]\n\
     Type=simple\n\
     ExecStart=/usr/local/lib/penguin/penguin --service\n\
     Restart=on-failure\n\
     RestartSec=5\n\
     \n\
     [Install]\n\
     WantedBy=multi-user.target\n";

pub(super) fn executable_from(unit: &str) -> Option<PathBuf> {
    let mut commands = unit
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("ExecStart="));
    let command = commands.next()?;
    if commands.next().is_some() {
        return None;
    }
    let literal = command.starts_with(':');
    let mut command = command.strip_prefix(':').unwrap_or(command);
    let first = word(&mut command)?;
    let path = if literal && first == "/bin/sh" {
        if word(&mut command)? != "-c" || word(&mut command)? != "exec \"$0\" \"$@\"" {
            return None;
        }
        word(&mut command)?
    } else {
        first
    };
    // Only accept the launch signature we own, including old unquoted units.
    if !path.starts_with('/') || word(&mut command)? != "--service" || !command.trim().is_empty() {
        return None;
    }
    Some(PathBuf::from(path))
}

fn word(input: &mut &str) -> Option<String> {
    let text = input.trim_start();
    let mut chars = text.char_indices();
    let mut quote = None;
    let mut value = String::new();
    while let Some((index, ch)) = chars.next() {
        if ch.is_ascii_whitespace() && quote.is_none() {
            *input = &text[index..];
            return (!value.is_empty()).then_some(value);
        }
        if ch == '\\' {
            value.push(unescape(chars.next()?.1)?);
        } else if ch == '%' {
            if chars.next()?.1 != '%' {
                return None;
            }
            value.push('%');
        } else if Some(ch) == quote {
            quote = None;
        } else if quote.is_none() && matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else {
            value.push(ch);
        }
    }
    *input = "";
    (quote.is_none() && !value.is_empty()).then_some(value)
}

fn unescape(ch: char) -> Option<char> {
    match ch {
        '\\' | '"' | '\'' => Some(ch),
        's' => Some(' '),
        _ => None,
    }
}

pub(super) fn absent(report: &str) -> bool {
    // Removing a unit file and reloading does not stop its running process.
    report.lines().any(|line| line == "LoadState=not-found")
        && report.lines().any(|line| line == "ActiveState=inactive")
}

pub(super) fn state_from(report: &str) -> PlatformResult<ServiceStatus> {
    let state = report
        .lines()
        .find_map(|line| line.strip_prefix("ActiveState="));
    match state {
        Some("active" | "reloading" | "refreshing") => Ok(ServiceStatus::Running),
        Some("activating" | "deactivating") => Ok(ServiceStatus::Transitioning),
        Some("inactive" | "failed" | "maintenance") => Ok(ServiceStatus::Stopped),
        _ => Err(PlatformError::Service(
            "systemctl returned no recognized ActiveState".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn the_unit_runs_the_staged_copy_and_keeps_its_restart_policy() {
        assert_eq!(
            executable_from(UNIT_TEXT).as_deref(),
            Some(Path::new(HELPER_PATH))
        );
        assert!(HELPER_PATH.starts_with(HELPER_DIR));
        // `Restart=always` подняло бы службу обратно после того, как окно
        // погасило её по просьбе человека: она выходит с нулевым кодом.
        assert!(UNIT_TEXT.contains("Restart=on-failure\nRestartSec=5"));
        assert!(UNIT_TEXT.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn old_simple_units_still_match() {
        assert_eq!(
            executable_from("[Service]\nExecStart=/usr/bin/penguin --service\n"),
            Some(PathBuf::from("/usr/bin/penguin"))
        );
        assert_eq!(
            executable_from("ExecStart=\"/opt/My Apps/penguin\" --service"),
            Some(PathBuf::from("/opt/My Apps/penguin"))
        );
    }

    #[test]
    fn stale_and_malformed_commands_do_not_match() {
        for command in [
            "",
            "/usr/bin/penguin",
            "/opt/--service/penguin",
            "/usr/bin/penguin --service-old",
            "\"/usr/bin/penguin --service",
            "/usr/bin/penguin --service extra",
            "/opt/%n/penguin --service",
            ":/usr/bin/env /usr/bin/penguin --service",
            ":/usr/bin/env -- /opt/name=value/penguin --service",
            ":/bin/sh -c 'something else' /usr/bin/penguin --service",
            "/bin/sh -c 'exec \"$0\" \"$@\"' /usr/bin/penguin --service",
            "/usr/bin/penguin --service\nExecStart=/bin/false",
        ] {
            assert!(
                executable_from(&format!("ExecStart={command}")).is_none(),
                "{command}"
            );
        }
    }

    #[test]
    fn properties_distinguish_transitions_and_bad_answers() {
        for (state, expected) in [
            ("active", ServiceStatus::Running),
            ("reloading", ServiceStatus::Running),
            ("refreshing", ServiceStatus::Running),
            ("activating", ServiceStatus::Transitioning),
            ("deactivating", ServiceStatus::Transitioning),
            ("inactive", ServiceStatus::Stopped),
            ("failed", ServiceStatus::Stopped),
            ("maintenance", ServiceStatus::Stopped),
        ] {
            assert_eq!(
                state_from(&format!("ActiveState={state}\n")).expect("state"),
                expected
            );
        }
        assert!(state_from("").is_err());
        assert!(state_from("Failed to connect to bus").is_err());
        assert!(state_from("ActiveState=unknown").is_err());
    }

    #[test]
    fn only_an_absent_inactive_unit_can_be_ignored() {
        assert!(absent("LoadState=not-found\nActiveState=inactive\n"));
        for report in [
            "",
            "LoadState=not-found\n",
            "LoadState=not-found\nActiveState=active\n",
            "LoadState=not-found\nActiveState=deactivating\n",
            "LoadState=loaded\nActiveState=inactive\n",
            "Failed to connect to bus",
        ] {
            assert!(!absent(report), "{report}");
        }
    }
}
