//! GeoIP за фичей `geo`. Пока базы нет, правила по странам ни с чем не совпадают.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use maxminddb::{Reader, geoip2};

use crate::matcher::Matcher;
use crate::target::MatchTarget;

/// База GeoIP, общая для задач.
#[derive(Clone)]
pub struct GeoIpDatabase {
    reader: Arc<Reader<Vec<u8>>>,
}

impl std::fmt::Debug for GeoIpDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoIpDatabase").finish_non_exhaustive()
    }
}

impl GeoIpDatabase {
    /// Открывает базу, читая файл целиком (отображённый на Windows не обновить).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let reader = Reader::open_readfile(path)
            .map_err(|e| format!("база GeoIP `{}`: {e}", path.display()))?;
        Ok(Self {
            reader: Arc::new(reader),
        })
    }

    /// Код страны адреса в верхнем регистре: `RU`, `DE`.
    pub fn country_of(&self, ip: IpAddr) -> Option<String> {
        let record: geoip2::Country = self.reader.lookup(ip).ok()?;
        record
            .country
            .or(record.registered_country)
            .and_then(|country| country.iso_code)
            .map(str::to_ascii_uppercase)
    }
}

/// Условие «адрес принадлежит одной из стран».
#[derive(Debug)]
pub struct GeoIpSet {
    database: GeoIpDatabase,
    countries: Vec<String>,
}

impl GeoIpSet {
    /// Собирает условие.
    pub fn new<I, S>(database: GeoIpDatabase, countries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            database,
            countries: countries
                .into_iter()
                .map(|c| c.as_ref().trim().to_ascii_uppercase())
                .collect(),
        }
    }
}

impl Matcher for GeoIpSet {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        let Some(country) = target
            .destination_ip
            .and_then(|ip| self.database.country_of(ip))
        else {
            return false;
        };
        self.countries.iter().any(|wanted| *wanted == country)
    }

    fn describe(&self) -> String {
        format!("страна в [{}]", self.countries.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_database_is_reported_not_panicking() {
        let err = GeoIpDatabase::open("такого-файла-нет.mmdb").expect_err("файла нет");
        assert!(err.contains("такого-файла-нет.mmdb"));
    }

    #[test]
    fn country_codes_are_normalized() {
        let normalized: Vec<String> = [" ru ", "De"]
            .iter()
            .map(|c| c.trim().to_ascii_uppercase())
            .collect();
        assert_eq!(normalized, vec!["RU".to_owned(), "DE".to_owned()]);
    }
}
