//! База стран по адресу: DB-IP Lite (CC BY 4.0) с релизов `sapics/ip-location-db`.
//!
//! Обновляется раз в месяц, поэтому старше [`MAX_AGE`] — скачивается заново.
//! SHA-256 лежит в соседнем релизе `checksum`.

use std::path::Path;
use std::time::{Duration, SystemTime};

#[cfg(feature = "net")]
use crate::error::{UpdateError, UpdateResult};

/// Имя файла базы в релизе.
#[cfg(feature = "net")]
const ASSET: &str = "dbip-country.mmdb";

/// Релизы, откуда берётся база.
#[cfg(feature = "net")]
const RELEASES: &str = "https://github.com/sapics/ip-location-db/releases/download";

/// База ~8 МБ; предел с запасом на рост.
#[cfg(feature = "net")]
const DATABASE_LIMIT: u64 = 64 * 1024 * 1024;

#[cfg(feature = "net")]
const SUMS_LIMIT: u64 = 4 * 1024;

/// Срок, после которого база обновляется: источник выпускает её ежемесячно.
pub const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Подпись, которой лицензия CC BY 4.0 требует там, где видны данные.
pub const ATTRIBUTION: &str = "IP Geolocation by DB-IP";

/// Нужно ли качать базу: её нет или она старше [`MAX_AGE`].
pub fn is_stale(path: &Path, now: SystemTime) -> bool {
    let Ok(modified) = std::fs::metadata(path).and_then(|meta| meta.modified()) else {
        return true;
    };
    now.duration_since(modified).is_ok_and(|age| age > MAX_AGE)
}

/// Скачивает базу, сверяет SHA-256 и подменяет `path` целиком.
#[cfg(feature = "net")]
pub fn download(path: &Path) -> UpdateResult<()> {
    let sums = crate::net::get(&format!("{RELEASES}/checksum/{ASSET}.sha256"), SUMS_LIMIT)?;
    let database = crate::net::get(&format!("{RELEASES}/latest/{ASSET}"), DATABASE_LIMIT)?;
    crate::checksum::verify(&database, &String::from_utf8_lossy(&sums), ASSET)?;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|err| UpdateError::io(dir, err))?;
    }
    // Читатель не увидит недописанный файл.
    let fresh = path.with_extension("mmdb.part");
    std::fs::write(&fresh, &database).map_err(|err| UpdateError::io(&fresh, err))?;
    std::fs::rename(&fresh, path).map_err(|err| {
        let _ = std::fs::remove_file(&fresh);
        UpdateError::io(path, err)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_database_is_stale() {
        assert!(is_stale(
            Path::new("нет-такой-базы.mmdb"),
            SystemTime::now()
        ));
    }

    #[test]
    fn a_fresh_database_is_kept_and_an_old_one_is_not() {
        let path = std::env::temp_dir().join(format!("penguin-geoip-{}.mmdb", std::process::id()));
        std::fs::write(&path, b"x").expect("запись");
        let now = SystemTime::now();

        assert!(!is_stale(&path, now));
        assert!(is_stale(&path, now + MAX_AGE + Duration::from_secs(60)));

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "net")]
    #[test]
    fn the_sources_are_allowed_hosts() {
        assert!(crate::net::check_url(&format!("{RELEASES}/latest/{ASSET}")).is_ok());
    }

    #[cfg(feature = "net")]
    #[test]
    fn the_published_sum_line_is_understood() {
        // Строка из `checksum/dbip-country.mmdb.sha256` на 2026-10-18.
        let line =
            "d4cdcb9ebeb79137733cbd42577be32ff5c2d7b24e072c6f4862a899265e9be3  dbip-country.mmdb";
        assert!(crate::checksum::expected_for(line, ASSET).is_ok());
    }
}
