//! Identity passed explicitly from the desktop process to the elevated helper.

use crate::IpcResult;

/// Effective Unix UID of this process; `None` on Windows.
///
/// Capture this in the desktop process, before elevation. Environment variables
/// such as `SUDO_UID` are deliberately not consulted.
pub fn current_user_id() -> Option<u32> {
    #[cfg(unix)]
    {
        Some(nix::unistd::geteuid().as_raw())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Approves one known Unix UID to control the privileged service.
///
/// Only an effective-root helper may call this successfully. UID zero is a
/// no-op and does not erase an existing approval. Returns `true` when the record
/// changes or an existing system socket is owned by a different UID, so callers
/// retry the listener restart even if a previous attempt saved the approval but
/// failed to restart. An unchanged record with no socket or matching ownership
/// returns `false`; this is not a service-readiness or full access check.
/// Socket inspection rejects unprotected/non-root-owned parent directories,
/// symlinks and non-socket entries rather than treating them as absent.
/// On Windows this returns [`crate::IpcError::AccessDenied`]; use the pipe ACL.
pub fn authorize_controller(uid: u32) -> IpcResult<bool> {
    #[cfg(unix)]
    {
        crate::controller::authorize(uid)
    }
    #[cfg(not(unix))]
    {
        let _ = uid;
        Err(crate::IpcError::AccessDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_the_effective_uid_not_an_environment_hint() {
        #[cfg(unix)]
        assert_eq!(current_user_id(), Some(nix::unistd::geteuid().as_raw()));
        #[cfg(windows)]
        {
            assert_eq!(current_user_id(), None);
            assert!(matches!(
                authorize_controller(1001),
                Err(crate::IpcError::AccessDenied)
            ));
        }
    }
}
