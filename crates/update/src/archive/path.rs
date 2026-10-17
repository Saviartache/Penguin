//! Имена внутри архива.

use crate::error::{UpdateError, UpdateResult};

/// Приводит имя к виду `a/b/c`: без `./`, лишних разделителей и обратных косых.
///
/// Абсолютные пути, `..` и диск (`C:`) — отказ.
pub(super) fn normalize(name: &str) -> UpdateResult<String> {
    let unsafe_path = || UpdateError::UnsafePath(name.escape_debug().to_string());
    let slashed = name.replace('\\', "/");
    if slashed.starts_with('/') || slashed.contains('\0') {
        return Err(unsafe_path());
    }

    let mut parts = Vec::new();
    for part in slashed.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err(unsafe_path()),
            part if part.contains(':') => return Err(unsafe_path()),
            part => parts.push(part),
        }
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_dotted_names_are_normalised() {
        assert_eq!(normalize("./penguin").expect("имя"), "penguin");
        assert_eq!(
            normalize("Penguin.app//Contents/./MacOS/penguin").expect("имя"),
            "Penguin.app/Contents/MacOS/penguin"
        );
        assert_eq!(normalize("dir\\file").expect("имя"), "dir/file");
        assert_eq!(normalize("./").expect("корень"), "");
    }

    #[test]
    fn names_that_climb_out_are_refused() {
        for name in [
            "../evil",
            "a/../../evil",
            "a/..",
            "..\\evil",
            "/etc/passwd",
            "\\windows\\system32",
            "C:/evil.exe",
            "C:evil.exe",
            "a\0b",
        ] {
            assert!(
                matches!(normalize(name), Err(UpdateError::UnsafePath(_))),
                "{name:?}"
            );
        }
    }
}
