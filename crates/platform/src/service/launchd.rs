//! Serialization and state parsing for Penguin-owned launchd jobs; no OS calls.

use std::path::PathBuf;

use super::ServiceStatus;
use crate::error::{PlatformError, PlatformResult};

pub(super) const TARGET: &str = "system/com.penguin.vpn";
pub(super) const PLIST_PATH: &str = "/Library/LaunchDaemons/com.penguin.vpn.plist";

/// Where the copy launchd actually executes lives.
///
/// launchd refuses to bootstrap a system daemon whose program sits where the
/// system does not vouch for its owner: a build tree, a user directory, an
/// external volume that is not even mounted when the machine boots. Shipped
/// clients answer this the same way — a root-owned copy under
/// `PrivilegedHelperTools`, registered instead of the original.
pub(super) const HELPER_DIR: &str = "/Library/PrivilegedHelperTools/Penguin";
pub(super) const HELPER_PATH: &str = "/Library/PrivilegedHelperTools/Penguin/penguin";

/// The job definition. Its program path is fixed, so nothing needs escaping.
pub(super) const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.penguin.vpn</string>
  <key>ProgramArguments</key>
  <array><string>/Library/PrivilegedHelperTools/Penguin/penguin</string><string>--service</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>ExitTimeOut</key><integer>10</integer>
  <key>StandardErrorPath</key><string>/var/log/penguin-service.log</string>
</dict>
</plist>
"#;

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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn the_job_runs_the_staged_copy_and_keeps_its_restart_policy() {
        assert_eq!(
            executable_from(PLIST).as_deref(),
            Some(Path::new(HELPER_PATH))
        );
        assert!(HELPER_PATH.starts_with(HELPER_DIR));
        assert!(PLIST.contains("<key>RunAtLoad</key><true/>"));
        assert!(PLIST.contains("<key>SuccessfulExit</key><false/>"));
        // Без него launchd выбрасывает поток ошибок целиком, и демон, упавший
        // до того, как открыл свой журнал, не оставляет ни строчки.
        assert!(PLIST.contains("<key>StandardErrorPath</key>"));
    }

    #[test]
    fn the_managed_target_names_the_job_label() {
        // Разошедшись, они дают задание, которое ставится и не управляется.
        let label = TARGET.strip_prefix("system/").expect("system domain");
        assert!(PLIST.contains(&format!("<string>{label}</string>")));
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
    fn an_escaped_legacy_path_is_read_back_whole() {
        // Прежние описания писались с путём внутри, и путь этот экранировался.
        let legacy = "<key>ProgramArguments</key><array><string>/opt/&amp;&lt;&gt;/penguin</string><string>--service</string></array>";
        assert_eq!(
            executable_from(legacy),
            Some(PathBuf::from("/opt/&<>/penguin"))
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
