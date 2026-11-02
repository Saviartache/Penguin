//! Учётная запись, от которой работает i2pd: служба — root, ему права не нужны.

/// Пользователь без прав.
pub const UNPRIVILEGED: &str = "nobody";

/// `uid` и `gid` пользователя [`UNPRIVILEGED`]; без него i2pd от root не запускается.
#[cfg(unix)]
pub fn unprivileged() -> crate::I2pdResult<(u32, u32)> {
    std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|passwd| find(&passwd, UNPRIVILEGED))
        .ok_or(crate::I2pdError::NoAccount(UNPRIVILEGED))
}

/// `uid` и `gid` из строки `/etc/passwd`; отрицательные (`-2` у macOS) — по модулю 2³².
pub fn find(passwd: &str, name: &str) -> Option<(u32, u32)> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        if fields.next()? != name {
            return None;
        }
        let _password = fields.next()?;
        let id = |raw: &str| raw.parse::<i64>().ok().map(|value| value as u32);
        Some((id(fields.next()?)?, id(fields.next()?)?))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_and_macos_spellings_are_read() {
        let linux = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
        assert_eq!(find(linux, "nobody"), Some((65534, 65534)));

        let macos =
            "##\n# User Database\nnobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false\n";
        assert_eq!(find(macos, "nobody"), Some((u32::MAX - 1, u32::MAX - 1)));
    }

    #[test]
    fn a_missing_or_broken_entry_is_none() {
        assert_eq!(find("nobodyelse:x:1:1::/:/bin/false\n", "nobody"), None);
        assert_eq!(find("nobody:x:abc:1::/:/bin/false\n", "nobody"), None);
        assert_eq!(find("nobody:x\n", "nobody"), None);
    }
}
