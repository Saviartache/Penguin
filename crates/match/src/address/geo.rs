//! GeoIP за фичей `geo`. Пока базы нет, правила по странам ни с чем не совпадают.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use maxminddb::Reader;
use serde::Deserialize;

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
        let record: Record<'_> = self.reader.lookup(ip).ok()?;
        record.code().map(str::to_ascii_uppercase)
    }
}

/// Запись страны в двух раскладках: GeoIP2 (`country.iso_code`) и плоской
/// (`country_code`, DB-IP Lite у `sapics/ip-location-db`).
#[derive(Debug, Deserialize)]
struct Record<'a> {
    #[serde(borrow)]
    country: Option<Named<'a>>,
    #[serde(borrow)]
    registered_country: Option<Named<'a>>,
    country_code: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct Named<'a> {
    iso_code: Option<&'a str>,
}

impl<'a> Record<'a> {
    fn code(&self) -> Option<&'a str> {
        let named = |named: &Option<Named<'a>>| named.as_ref().and_then(|n| n.iso_code);
        self.country_code
            .or_else(|| named(&self.country))
            .or_else(|| named(&self.registered_country))
            .filter(|code| !code.is_empty())
    }
}

/// Условие «адрес принадлежит одной из стран».
#[derive(Debug)]
pub struct GeoIpSet {
    database: Option<GeoIpDatabase>,
    countries: Vec<String>,
}

impl GeoIpSet {
    /// Собирает условие; без базы оно не совпадает ни с чем, но набор правил
    /// собирается: база приезжает к службе позже настроек.
    pub fn new<I, S>(database: Option<GeoIpDatabase>, countries: I) -> Self
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
        let (Some(database), Some(ip)) = (&self.database, target.destination_ip) else {
            return false;
        };
        database
            .country_of(ip)
            .is_some_and(|country| self.countries.contains(&country))
    }

    fn describe(&self) -> String {
        let countries = self.countries.join(", ");
        match self.database {
            Some(_) => format!("страна в [{countries}]"),
            None => format!("страна в [{countries}] (база GeoIP не загружена)"),
        }
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

    fn code_of(json: &str) -> Option<String> {
        let record: Record<'_> = serde_json::from_str(json).expect("запись");
        record.code().map(str::to_owned)
    }

    #[test]
    fn both_record_layouts_give_the_country() {
        assert_eq!(code_of(r#"{"country_code":"JP"}"#).as_deref(), Some("JP"));
        assert_eq!(
            code_of(r#"{"country":{"iso_code":"DE","names":{"en":"Germany"}}}"#).as_deref(),
            Some("DE")
        );
        assert_eq!(
            code_of(r#"{"registered_country":{"iso_code":"NL"}}"#).as_deref(),
            Some("NL")
        );
        assert_eq!(code_of(r#"{"continent":{"code":"EU"}}"#), None);
    }

    #[test]
    fn without_a_database_nothing_matches() {
        let set = GeoIpSet::new(None, ["RU"]);
        assert!(!set.matches(&crate::test_support::target()));
        assert!(set.describe().contains("не загружена"));
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
