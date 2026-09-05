//! Serialization of Penguin-owned systemd units, without OS calls.

use std::path::{Path, PathBuf};

use super::ServiceStatus;
use crate::error::{PlatformError, PlatformResult};

pub(super) fn unit(executable: &Path) -> PlatformResult<String> {
    let path = executable
        .to_str()
        .filter(|path| path.starts_with('/') && !path.chars().any(char::is_control))
        .ok_or_else(|| {
            PlatformError::Service(
                "executable must be an absolute UTF-8 path without control characters".into(),
            )
        })?;

    // systemd rejects quotes/backslashes in the executable itself, even escaped.
    // A fixed shell script execs the path as data, never as shell source. env
    // cannot do this for paths containing '=': it treats them as assignments.
    // ':' disables systemd's $ expansion; %% still escapes unit specifiers.
    let path = path
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    Ok(format!(
        "[Unit]\n\
         Description=Penguin VPN\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart=:/bin/sh -c 'exec \"$0\" \"$@\"' \"{path}\" --service\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    ))
}

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
    use super::*;

    #[test]
    fn unit_keeps_the_path_out_of_shell_source() {
        let text = unit(Path::new("/opt/my \"app\"/it's\\$HOME%/penguin")).expect("unit");
        assert!(text.contains(
            r#"ExecStart=:/bin/sh -c 'exec "$0" "$@"' "/opt/my \"app\"/it's\\$HOME%%/penguin" --service"#
        ));
        assert!(text.contains("Restart=on-failure\nRestartSec=5"));
        assert!(text.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn executable_round_trips() {
        for path in [
            "/usr/bin/penguin",
            "/opt/My Apps/penguin",
            "/opt/\"quotes\"/penguin",
            "/opt/it's/penguin",
            "/opt/back\\slash/penguin",
            "/opt/$HOME${USER}$$/penguin",
            "/opt/%n%%/penguin",
            "/opt/\u{41f}\u{438}\u{43d}\u{433}\u{432}\u{438}\u{43d}/penguin",
            "/opt/--service/penguin",
            "/opt/[glob]*?/penguin",
            "/opt/name=value/penguin",
            "/opt/$(touch marker);`id`/penguin",
            "/opt/penguin ",
        ] {
            let text = unit(Path::new(path)).expect("unit");
            let parsed = executable_from(&text).expect("executable");
            assert_eq!(parsed.to_str(), Some(path), "{text}");
        }
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
    fn invalid_paths_are_rejected_before_writing() {
        for path in [
            "",
            "relative/penguin",
            "/opt/line\nbreak",
            "/opt/tab\tname",
            "/opt/nul\0name",
        ] {
            assert!(unit(Path::new(path)).is_err());
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
