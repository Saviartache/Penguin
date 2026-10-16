//! Linux: запуск разрешает правило polkit; `systemctl` просит systemd через D-Bus.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use nix::unistd::{Uid, User};

use super::polkit::{RULE_PATH, RULES_DIR, rule_for};
use crate::command;
use crate::error::{PlatformError, PlatformResult};
use crate::service::linux::SYSTEMCTL;
use crate::service::stage::at;
use crate::service::systemd::UNIT;

pub(super) fn allow(controller_uid: Option<u32>) -> PlatformResult<()> {
    let Some(uid) = controller_uid else {
        return Ok(());
    };
    if !Path::new(RULES_DIR).is_dir() {
        // До 0.106 polkit читает только .pkla, а они не различают юниты.
        tracing::warn!("нет {RULES_DIR}: запуск службы из окна будет спрашивать пароль");
        return Ok(());
    }
    let rule = rule_for(&user_name(uid)?).ok_or_else(|| {
        PlatformError::Service("имя пользователя не годится для правила polkit".to_owned())
    })?;

    let path = Path::new(RULE_PATH);
    let temporary = path.with_extension("new");
    std::fs::write(&temporary, rule).map_err(|err| at(&temporary, &err))?;
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o644))
        .map_err(|err| at(&temporary, &err))?;
    std::fs::rename(&temporary, path).map_err(|err| at(path, &err))
}

pub(super) fn request() -> PlatformResult<()> {
    let granted = user_name(Uid::effective().as_raw())
        .ok()
        .and_then(|name| rule_for(&name))
        .is_some_and(|rule| std::fs::read_to_string(RULE_PATH).is_ok_and(|text| text == rule));
    if !granted {
        return Err(PlatformError::PermissionDenied(
            "запуск службы без пароля не разрешён".to_owned(),
        ));
    }
    // Вопрос о пароле здесь значил бы, что правило не сработало.
    command::run(SYSTEMCTL, &["--no-ask-password", "start", UNIT])
        .map(|_| ())
        .map_err(|err| err.into_error(PlatformError::Service, "запуск службы"))
}

fn user_name(uid: u32) -> PlatformResult<String> {
    User::from_uid(Uid::from_raw(uid))
        .map_err(|err| PlatformError::Service(format!("учётная запись {uid}: {err}")))?
        .map(|user| user.name)
        .ok_or_else(|| PlatformError::Service(format!("нет учётной записи {uid}")))
}
