//! Файл от окна кусками: дописываются в `part` по порядку.

use std::io::Write;
use std::path::Path;

use penguin_ipc::schema::request::GEOIP_CHUNK;

/// Дописывает кусок `what`; `true` — файл пришёл целиком.
pub(super) fn write_chunk(
    part: &Path,
    limit: u64,
    what: &str,
    offset: u64,
    total: u64,
    data: &[u8],
) -> Result<bool, String> {
    let end = offset.saturating_add(data.len() as u64);
    if total > limit || data.len() > GEOIP_CHUNK || end > total {
        return Err(format!(
            "кусок {what} вне пределов: {offset}+{} из {total}",
            data.len()
        ));
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(offset == 0)
        .append(offset != 0)
        .open(part)
        .map_err(|err| format!("{}: {err}", part.display()))?;
    let written = file
        .metadata()
        .map_err(|err| format!("{}: {err}", part.display()))?
        .len();
    if written != offset {
        return Err(format!(
            "кусок {what} не по порядку: ждали {written}, пришёл {offset}"
        ));
    }
    file.write_all(data)
        .map_err(|err| format!("{}: {err}", part.display()))?;
    Ok(end == total)
}
