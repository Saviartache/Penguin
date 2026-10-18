//! Страны серверов для флагов: что уже известно и о чём уже спросили.
//!
//! Страна из профиля ([`Profile::country`]) главнее GeoIP: у подписки адрес
//! общий для всех локаций, и GeoIP назвал бы страну входа.
//!
//! Спрашивают один раз за запуск: сервер без страны в базе не переспрашивается,
//! а неудачный запрос снимает отметку — повторится со следующим поводом.

use std::collections::{HashMap, HashSet};

use penguin_config::schema::profile::Profile;

use crate::flags::Flag;
use crate::screens::servers::server_of;

/// Страны по адресу сервера (`хост:порт`, как в профиле).
#[derive(Debug, Default)]
pub struct Countries {
    known: HashMap<String, String>,
    asked: HashSet<String>,
}

impl Countries {
    /// Флаг профиля: страна от источника профиля, иначе найденная GeoIP.
    pub fn flag(&self, profile: &Profile) -> Option<Flag> {
        match &profile.country {
            Some(code) => Flag::of(code),
            None => server_of(profile)
                .and_then(|server| self.known.get(server))
                .and_then(|code| Flag::of(code)),
        }
    }

    /// Серверы, чью страну надо спросить у GeoIP: у профиля своей нет.
    pub fn wanted(profiles: &[Profile]) -> impl Iterator<Item = &str> {
        profiles
            .iter()
            .filter(|profile| profile.country.is_none())
            .filter_map(server_of)
    }

    /// Известна ли хоть одна страна: тогда видна подпись источника данных.
    pub fn any(&self) -> bool {
        !self.known.is_empty()
    }

    /// Отмечает и отдаёт серверы, о которых ещё не спрашивали.
    pub fn unasked<'a>(&mut self, servers: impl IntoIterator<Item = &'a str>) -> Vec<String> {
        let mut fresh = Vec::new();
        for server in servers {
            if self.asked.insert(server.to_owned()) {
                fresh.push(server.to_owned());
            }
        }
        fresh
    }

    /// Ответ пришёл: запоминает найденные страны.
    pub fn located(&mut self, found: HashMap<String, String>) {
        self.known.extend(found);
    }

    /// Запрос не удался: эти серверы спросят снова.
    pub fn failed(&mut self, servers: &[String]) {
        for server in servers {
            self.asked.remove(server);
        }
    }
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::outbound::RawOutbound;
    use serde_json::json;

    use super::*;

    #[test]
    fn a_server_is_asked_about_once() {
        let mut countries = Countries::default();
        assert_eq!(
            countries.unasked(["a:1", "b:2", "a:1"]),
            vec!["a:1".to_owned(), "b:2".to_owned()]
        );
        assert!(countries.unasked(["a:1", "b:2"]).is_empty());
    }

    #[test]
    fn a_failed_request_is_retried() {
        let mut countries = Countries::default();
        let asked = countries.unasked(["a:1"]);
        countries.failed(&asked);
        assert_eq!(countries.unasked(["a:1"]), asked);
    }

    fn profile(server: &str, country: Option<&str>) -> Profile {
        let mut profile = Profile::new(
            server,
            server,
            RawOutbound::new("wireguard", json!({ "server": server })),
        );
        profile.country = country.map(str::to_owned);
        profile
    }

    #[test]
    fn a_located_server_gets_its_flag() {
        let mut countries = Countries::default();
        assert!(!countries.any());
        countries.located(HashMap::from([
            ("a:1".to_owned(), "JP".to_owned()),
            ("b:2".to_owned(), "ZZ".to_owned()),
        ]));
        assert!(countries.any());
        assert_eq!(countries.flag(&profile("a:1", None)), Flag::of("jp"));
        assert_eq!(countries.flag(&profile("b:2", None)), None);
        assert_eq!(countries.flag(&profile("c:3", None)), None);
    }

    #[test]
    fn the_profile_country_beats_the_shared_entry_address() {
        // Локации подписки за одним входом: GeoIP знает только страну входа.
        let mut countries = Countries::default();
        countries.located(HashMap::from([("gw:1".to_owned(), "DE".to_owned())]));

        assert_eq!(countries.flag(&profile("gw:1", Some("NL"))), Flag::of("nl"));
        let profiles = [profile("gw:1", Some("NL")), profile("x:2", None)];
        assert_eq!(Countries::wanted(&profiles).collect::<Vec<_>>(), ["x:2"]);
    }
}
