//! Serialization and state parsing for Penguin-owned launchd jobs; no OS calls.

use std::path::{Path, PathBuf};

use super::ServiceStatus;
use crate::error::{PlatformError, PlatformResult};

pub(super) const TARGET: &str = "system/com.penguin.vpn";
pub(super) const PLIST_PATH: &str = "/Library/LaunchDaemons/com.penguin.vpn.plist";

pub(super) fn plist(executable: &Path) -> PlatformResult<String> {
    let path = executable
        .to_str()
        .filter(|path| {
            path.starts_with('/')
                && !path
                    .chars()
                    .any(|ch| ch.is_control() || matches!(ch, '\u{fffe}' | '\u{ffff}'))
        })
        .ok_or_else(|| {
            PlatformError::Service(
                "executable must be an absolute UTF-8 path valid in XML, without control characters"
                    .into(),
            )
        })?;
    let path = path
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
           <key>Label</key><string>com.penguin.vpn</string>\n\
           <key>ProgramArguments</key>\n\
           <array><string>{path}</string><string>--service</string></array>\n\
           <key>RunAtLoad</key><true/>\n\
           <key>KeepAlive</key>\n\
           <dict><key>SuccessfulExit</key><false/></dict>\n\
         </dict>\n\
         </plist>\n"
    ))
}

pub(super) fn executable_from(plist: &str) -> Option<PathBuf> {
    let arguments = plist
        .split_once("<key>ProgramArguments</key>")?
        .1
        .trim_start();
    let mut arguments = arguments.strip_prefix("<array>")?.split_once("</array>")?.0;
    let path = string(&mut arguments)?;
    if !path.starts_with('/')
        || string(&mut arguments)? != "--service"
        || !arguments.trim().is_empty()
    {
        return None;
    }
    Some(PathBuf::from(path))
}

fn string(input: &mut &str) -> Option<String> {
    let (value, rest) = input
        .trim_start()
        .strip_prefix("<string>")?
        .split_once("</string>")?;
    *input = rest;
    Some(
        value
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&"),
    )
}

pub(super) fn state_from(report: &str) -> PlatformResult<ServiceStatus> {
    let state = report
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("state = "));
    match state {
        Some("running") => Ok(ServiceStatus::Running),
        Some("spawn scheduled" | "spawning" | "starting" | "terminating") => {
            Ok(ServiceStatus::Transitioning)
        }
        Some(_) => Ok(ServiceStatus::Stopped),
        None => Err(PlatformError::Service(
            "launchctl returned no service state".into(),
        )),
    }
}

/// Service-not-found exit codes: bootout uses ESRCH (3), print uses 113.
pub(super) fn absent(code: Option<i32>) -> bool {
    matches!(code, Some(3 | 113))
}

pub(super) fn start_commands(loaded: bool) -> Vec<Vec<&'static str>> {
    let mut commands = vec![vec!["enable", TARGET]];
    if !loaded {
        commands.push(vec!["bootstrap", "system", PLIST_PATH]);
    }
    commands.push(vec!["kickstart", TARGET]);
    commands
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_round_trips_and_keeps_restart_policy() {
        for path in [
            "/usr/local/bin/penguin",
            "/Applications/Links & <copies>/penguin",
            "/Applications/&amp;&lt;&gt;/penguin",
            "/Applications/\"it's\"\\$%/penguin",
            "/Applications/\u{41f}\u{438}\u{43d}\u{433}\u{432}\u{438}\u{43d}/penguin",
            "/opt/penguin ",
        ] {
            let text = plist(Path::new(path)).expect("plist");
            assert_eq!(executable_from(&text).expect("path").to_str(), Some(path));
            assert!(text.contains("<key>RunAtLoad</key><true/>"));
            assert!(text.contains("<key>SuccessfulExit</key><false/>"));
        }
    }

    #[test]
    fn old_plist_and_stale_role_are_distinguished() {
        let old = "<key>ProgramArguments</key>\n <array>\n <string>/opt/penguin</string>\n <string>--service</string>\n </array>";
        assert_eq!(executable_from(old), Some(PathBuf::from("/opt/penguin")));
        assert!(executable_from(&old.replace("<string>--service</string>", "")).is_none());
        assert!(executable_from(&old.replace("--service", "--service-old")).is_none());
        assert!(executable_from("<key>ProgramArguments</key><array><string>/opt/penguin</string></array><string>--service</string>").is_none());
        assert!(
            executable_from(&old.replace("</array>", "<string>extra</string></array>")).is_none()
        );
        assert!(executable_from(&old.replace("/opt/penguin", "relative/penguin")).is_none());
        assert!(executable_from("<plist><dict></dict></plist>").is_none());
    }

    #[test]
    fn invalid_paths_are_rejected_before_writing() {
        for path in [
            "",
            "relative/penguin",
            "/opt/line\nbreak",
            "/opt/tab\tname",
            "/opt/nul\0name",
            "/opt/\u{fffe}/penguin",
            "/opt/\u{ffff}/penguin",
        ] {
            assert!(plist(Path::new(path)).is_err(), "{path:?}");
        }
    }

    #[test]
    fn start_enables_before_loading_and_never_kills() {
        assert_eq!(
            start_commands(false),
            vec![
                vec!["enable", TARGET],
                vec!["bootstrap", "system", PLIST_PATH],
                vec!["kickstart", TARGET]
            ]
        );
        assert_eq!(
            start_commands(true),
            vec![vec!["enable", TARGET], vec!["kickstart", TARGET]]
        );
    }

    #[test]
    fn only_absence_is_ignored() {
        assert!(absent(Some(3)));
        assert!(absent(Some(113)));
        for code in [None, Some(1), Some(5), Some(13), Some(127)] {
            assert!(!absent(code));
        }
    }

    #[test]
    fn service_state_precedes_nested_state() {
        for (state, expected) in [
            ("running", ServiceStatus::Running),
            ("spawn scheduled", ServiceStatus::Transitioning),
            ("spawning", ServiceStatus::Transitioning),
            ("starting", ServiceStatus::Transitioning),
            ("terminating", ServiceStatus::Transitioning),
            ("not running", ServiceStatus::Stopped),
        ] {
            assert_eq!(
                state_from(&format!(
                    "state = {state}\nresource coalition = {{\n state = active\n}}\n"
                ))
                .expect("state"),
                expected
            );
        }
        assert!(state_from("").is_err());
        assert!(state_from("Could not find service").is_err());
    }
}
