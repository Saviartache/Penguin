//! Отпечаток собранного файла: по времени правки видно, что служба держит старый образ.

/// Отпечаток исполняемого файла; пустая строка — узнать не удалось.
pub fn stamp() -> String {
    let Ok(executable) = std::env::current_exe() else {
        return String::new();
    };
    let Ok(modified) = executable.metadata().and_then(|meta| meta.modified()) else {
        return String::new();
    };

    modified
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs().to_string())
        .unwrap_or_default()
}

/// Разошлись ли отпечатки настолько, что службу пора перезапустить; пустой отпечаток — не улика.
pub fn is_stale(running: &str, current: &str) -> bool {
    if running.is_empty() || current.is_empty() {
        return false;
    }
    running != current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_running_build_knows_itself() {
        assert!(!stamp().is_empty());
    }

    #[test]
    fn different_stamps_mean_a_stale_service() {
        assert!(is_stale("1700000000", "1700000900"));
    }

    #[test]
    fn the_same_stamp_is_left_alone() {
        assert!(!is_stale("1700000000", "1700000000"));
    }

    #[test]
    fn silence_is_not_evidence() {
        assert!(!is_stale("", "1700000000"));
        assert!(!is_stale("1700000000", ""));
        assert!(!is_stale("", ""));
    }
}
