//! Pure Unix control-channel policy, also tested on Windows.

#[cfg(any(unix, test))]
pub(crate) fn permits(peer: u32, daemon: u32, approved: Option<u32>, administrator: bool) -> bool {
    peer == 0 || peer == daemon || administrator || (daemon == 0 && approved == Some(peer))
}

#[cfg(any(unix, test))]
pub(crate) fn trusts_server(peer: Option<u32>, expected: u32) -> bool {
    peer == Some(expected)
}

#[cfg(any(unix, test))]
pub(crate) fn private_record(
    owner: u32,
    mode: u32,
    regular: bool,
    links: u64,
    expected: u32,
) -> bool {
    owner == expected && mode & 0o7777 == 0o600 && regular && links == 1
}

#[cfg(any(unix, test))]
pub(crate) fn protected_directory(owner: u32, mode: u32, directory: bool, expected: u32) -> bool {
    owner == expected && mode & 0o022 == 0 && directory
}

#[cfg(any(unix, test))]
pub(crate) fn parse_controller(raw: &str) -> Option<u32> {
    let digits = raw.strip_suffix('\n').unwrap_or(raw);
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits
        .parse()
        .ok()
        .filter(|uid| *uid != 0 && *uid != u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_approval_does_not_depend_on_admin_group_selection() {
        assert!(permits(1001, 0, Some(1001), false));
        assert!(!permits(1002, 0, Some(1001), false));
        assert!(!permits(1001, 0, None, false));
        assert!(permits(1002, 0, None, true));
        assert!(permits(0, 1000, None, false));
        assert!(permits(1000, 1000, None, false));
        assert!(!permits(1001, 1000, Some(1001), false));
    }

    #[test]
    fn clients_require_the_expected_server_identity() {
        assert!(trusts_server(Some(0), 0));
        assert!(!trusts_server(Some(1000), 0));
        assert!(trusts_server(Some(1000), 1000));
        assert!(!trusts_server(Some(1001), 1000));
        assert!(!trusts_server(None, 0));
    }

    #[test]
    fn approval_record_must_be_private_regular_and_root_owned() {
        assert!(private_record(0, 0o100600, true, 1, 0));
        for mode in [0o644, 0o660, 0o666, 0o4600] {
            assert!(!private_record(0, mode, true, 1, 0));
        }
        assert!(!private_record(1000, 0o600, true, 1, 0));
        assert!(!private_record(0, 0o600, false, 1, 0));
        assert!(!private_record(0, 0o600, true, 2, 0));
        assert!(protected_directory(0, 0o751, true, 0));
        assert!(!protected_directory(0, 0o775, true, 0));
        assert!(!protected_directory(1000, 0o751, true, 0));
    }

    #[test]
    fn approval_is_exactly_one_nonroot_uid() {
        assert_eq!(parse_controller("1001\n"), Some(1001));
        assert_eq!(parse_controller("501"), Some(501));
        for raw in [
            "",
            "0",
            "4294967295",
            "4294967296",
            "-1",
            " 501",
            "501 502",
            "501\n502",
            "501\n\n",
        ] {
            assert_eq!(parse_controller(raw), None, "{raw:?}");
        }
    }
}
