//! Windows: право запуска (`RP`) вошедшему пользователю в DACL службы; SCM проверяет его сам.

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT, SetServiceObjectSecurity,
};
use windows::core::{PCWSTR, w};

use crate::error::{PlatformError, PlatformResult};

/// DACL службы по умолчанию, где IU (вошедший пользователь) получил ещё и запуск (`RP`).
const SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)\
                    (A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

/// `WRITE_DAC`: право сменить DACL.
const WRITE_DAC: u32 = 0x0004_0000;

#[allow(unsafe_code, reason = "смена дескриптора безопасности службы")]
pub(super) fn allow() -> PlatformResult<()> {
    let sddl: Vec<u16> = SDDL.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` оканчивается нулём и живёт до конца вызова.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|err| PlatformError::Service(format!("дескриптор службы: {err}")))?;

    // SAFETY: строки — константы с нулём; описатели закрываются ровно раз, дескриптор
    // освобождается после последнего использования.
    let result = unsafe {
        let applied = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT).and_then(
            |manager| {
                let applied =
                    OpenServiceW(manager, w!("PenguinVpn"), WRITE_DAC).and_then(|service| {
                        let applied = SetServiceObjectSecurity(
                            service,
                            DACL_SECURITY_INFORMATION,
                            descriptor,
                        );
                        let _ = CloseServiceHandle(service);
                        applied
                    });
                let _ = CloseServiceHandle(manager);
                applied
            },
        );
        LocalFree(HLOCAL(descriptor.0));
        applied
    };
    result.map_err(|err| PlatformError::Service(format!("право запуска службы: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_desktop_user_may_start_but_not_stop_or_reconfigure() {
        let user = SDDL
            .split(')')
            .find(|ace| ace.ends_with(";;;IU"))
            .expect("запись IU");
        assert!(user.contains("RP"), "{user}");
        for right in ["WP", "DC", "WD", "WO", "SD"] {
            assert!(!user.contains(right), "{right} в {user}");
        }
    }

    #[test]
    fn the_service_name_matches() {
        assert_eq!(crate::service::SERVICE_NAME, "PenguinVpn");
    }
}
