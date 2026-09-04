//! Загрузочное разрешение имён: как клиент узнаёт адрес своего сервера.
//!
//! # Почему не системным резолвером
//!
//! Замкнутый круг. Клиент перехватывает разрешение имён — объявляет своим
//! адресом единственный DNS системы и отвечает подставными адресами из своей
//! же подсети. Спросив системный резолвер об имени своего сервера, он получает
//! подставной адрес и звонит сам себе; снаружи это «рукопожатие не
//! завершилось: timed out».
//!
//! Хуже того, круг переживает сам клиент. Демон, убитый без отката, оставляет
//! системный DNS смотреть в исчезнувший адаптер — и следующий запуск не может
//! разрешить имя сервера **до** того, как поднимет тоннель. Выбраться из этого
//! системным резолвером нельзя вовсе.
//!
//! Поэтому имя сервера спрашивается у своих апстримов напрямую
//! (`dns.bootstrap` в настройках), мимо системы и мимо тоннеля.
//!
//! # Когда своих апстримов не хватает
//!
//! Публичный резолвер бывает недостижим: провайдер режет порт 53, до адреса
//! нет маршрута, машина за строгим брандмауэром. Системный резолвер в таких
//! сетях обычно работает — он ходит через настроенную службу, а не своим
//! сокетом наружу, — и отказываться от него значило бы оставить человека без
//! связи там, где связь есть.
//!
//! Поэтому он остаётся запасным путём: спрашивается последним, и **ответ его
//! проверяется**. Адрес из подсети подставных — это мы сами, и такой ответ
//! отбрасывается. Круг остаётся разорванным, а сеть, где иначе ничего бы не
//! вышло, — рабочей.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::rr::RecordType;

use crate::config::Upstream as UpstreamConfig;
use crate::error::{DnsError, DnsResult};
use crate::message;
use crate::resolver::Resolver;
use crate::upstream::Upstream;

/// Разрешатель, которым спрашивают имя сервера.
///
/// Загрузочный, а системный — только если загрузочного не из чего собрать:
/// разрешать имена плохо лучше, чем никак.
///
/// Отдельная функция, потому что спрашивают в трёх местах — служба, локальный
/// прокси и проверка профилей, — и во всех трёх ошибка одна и та же: взять
/// системный, потому что «тоннель ведь ещё не поднят». Тоннеля может не быть, а
/// подмена DNS от прошлого запуска — быть.
pub fn resolver_for(config: &crate::config::DnsConfig) -> Arc<dyn Resolver> {
    // Подсеть подставных адресов — та же, что у перехвата. Ошибку в ней здесь
    // не разбираем: её ловит проверка настроек, а без подсети разрешение имён
    // работает, просто без последней проверки ответа.
    let fake_ip = crate::fakeip::FakeIpPool::parse(&config.fake_ip_range).ok();

    match BootstrapResolver::from_config(&config.bootstrap) {
        Ok(bootstrap) => Arc::new(bootstrap.rejecting(fake_ip)),
        Err(err) => {
            tracing::warn!(%err, "загрузочное разрешение имён не собрано");
            Arc::new(crate::resolver::SystemResolver)
        }
    }
}

/// Разрешение имён мимо системы и мимо тоннеля.
pub struct BootstrapResolver {
    /// Куда спрашивать. Список — запасные пути друг для друга.
    upstreams: Vec<Arc<dyn Upstream>>,
    /// Подсеть подставных адресов — то, чему верить нельзя.
    ///
    /// Нужна запасному пути. Системный резолвер зовут, только когда свои
    /// апстримы молчат, и он может оказаться подменённым: тогда он отвечает
    /// адресом из этой подсети, и принять такой ответ значит позвонить самому
    /// себе.
    fake_ip: Option<crate::fakeip::FakeIpPool>,
}

impl std::fmt::Debug for BootstrapResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapResolver")
            .field("upstreams", &self.upstreams.len())
            .finish()
    }
}

impl BootstrapResolver {
    /// Собирает разрешатель по настройкам загрузочных апстримов.
    pub fn from_config(configs: &[UpstreamConfig]) -> DnsResult<Self> {
        Ok(Self {
            upstreams: crate::upstream::build_all(configs)?,
            fake_ip: None,
        })
    }

    /// Учит отвергать адреса из подсети подставных.
    pub fn rejecting(mut self, fake_ip: Option<crate::fakeip::FakeIpPool>) -> Self {
        self.fake_ip = fake_ip;
        self
    }

    /// Запасной путь: спросить систему и не поверить ей на слово.
    ///
    /// Свои апстримы бывают недостижимы — их режет провайдер, до них нет
    /// маршрута, машина за строгим брандмауэром. Системный резолвер в таких
    /// сетях обычно работает: он ходит через настроенную службу, а не своим
    /// сокетом наружу.
    ///
    /// Опасность у него ровно одна — та, ради которой всё это и затевалось:
    /// он может быть подменён нами же и ответить подставным адресом. Значит,
    /// проверяем ответ, а не отказываемся от него.
    async fn ask_the_system(&self, host: &str) -> Vec<IpAddr> {
        use crate::resolver::SystemResolver;

        let Ok(addresses) = SystemResolver.resolve(host).await else {
            return Vec::new();
        };

        addresses
            .into_iter()
            .filter(|address| !self.is_fake(*address))
            .collect()
    }

    /// Подставной ли это адрес — то есть наш собственный.
    fn is_fake(&self, address: IpAddr) -> bool {
        let (Some(pool), IpAddr::V4(v4)) = (&self.fake_ip, address) else {
            return false;
        };
        pool.contains(v4)
    }

    /// Спрашивает апстримы по очереди, пока кто-нибудь не ответит.
    ///
    /// Первый ответивший и отвечает. Обходить весь список ради «лучшего»
    /// ответа незачем: адрес сервера у них один и тот же, а лишний обход — это
    /// лишние секунды перед подключением.
    async fn ask(&self, host: &str, record_type: RecordType) -> Vec<IpAddr> {
        for upstream in &self.upstreams {
            let Ok(query) = message::build_query(host, record_type, rand::random()) else {
                continue;
            };

            match upstream.query(&query).await {
                Ok(answer) => match message::extract_addresses(&answer) {
                    Ok(addresses) if !addresses.is_empty() => return addresses,
                    // Пустой ответ — не отказ апстрима, а «такого имени нет».
                    // Спрашивать остальных о том же смысла нет, но и обрывать
                    // на этом не будем: у имени может не быть записи этого
                    // типа, а быть — другого.
                    Ok(_) => break,
                    Err(err) => tracing::debug!(%err, "загрузочный ответ не разбирается"),
                },
                Err(err) => tracing::debug!(
                    upstream = upstream.describe(),
                    %err,
                    "загрузочный апстрим не ответил"
                ),
            }
        }
        Vec::new()
    }
}

#[async_trait]
impl Resolver for BootstrapResolver {
    async fn resolve(&self, host: &str) -> DnsResult<Vec<IpAddr>> {
        // Числовой адрес спрашивать не у кого — он и есть ответ. Проверка не
        // для скорости: сервер часто задан адресом, а запрос об адресе как об
        // имени вернул бы «такого имени нет».
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(vec![address]);
        }

        let mut addresses = self.ask(host, RecordType::A).await;
        // IPv6 — только когда IPv4 нет. Спрашивать оба всегда значило бы
        // удваивать ожидание перед каждым подключением ради адреса, которым в
        // большинстве сетей всё равно не воспользуются.
        if addresses.is_empty() {
            addresses = self.ask(host, RecordType::AAAA).await;
        }

        // Свои апстримы молчат — спрашиваем систему. Это запасной путь, а не
        // равноправный: он идёт последним и его ответу не верят на слово.
        if addresses.is_empty() {
            tracing::debug!(host, "загрузочные апстримы молчат — спрашиваю систему");
            addresses = self.ask_the_system(host).await;
        }

        if addresses.is_empty() {
            return Err(DnsError::Upstream(format!(
                "адрес `{host}` не назвали ни загрузочные апстримы, ни система"
            )));
        }
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Апстрим, который отвечает заранее заданным.
    struct Canned(DnsResult<Vec<u8>>);

    #[async_trait]
    impl Upstream for Canned {
        fn describe(&self) -> String {
            "проба".to_owned()
        }

        async fn query(&self, _request: &[u8]) -> DnsResult<Vec<u8>> {
            match &self.0 {
                Ok(answer) => Ok(answer.clone()),
                Err(err) => Err(DnsError::Upstream(err.to_string())),
            }
        }
    }

    /// Ответ с одним адресом.
    fn answer(host: &str, address: IpAddr) -> Vec<u8> {
        let question = message::Question {
            name: host.to_owned(),
            record_type: message::record_type_of(address),
            id: 1,
        };
        message::build_answer(&question, &[address], 60).expect("ответ собирается")
    }

    fn resolver(upstreams: Vec<Arc<dyn Upstream>>) -> BootstrapResolver {
        BootstrapResolver {
            upstreams,
            fake_ip: None,
        }
    }

    /// Разрешатель, знающий подсеть подставных адресов из настроек.
    fn guarded(upstreams: Vec<Arc<dyn Upstream>>) -> BootstrapResolver {
        resolver(upstreams).rejecting(crate::fakeip::FakeIpPool::parse("198.18.0.0/15").ok())
    }

    #[tokio::test]
    async fn a_numeric_server_needs_no_lookup() {
        // Сервер часто задан адресом. Запрос об адресе как об имени вернул бы
        // «такого имени нет», и клиент не подключился бы вовсе.
        let addresses = resolver(Vec::new())
            .resolve("45.150.33.10")
            .await
            .expect("адрес разбирается");
        assert_eq!(
            addresses,
            ["45.150.33.10".parse::<IpAddr>().expect("адрес")]
        );
    }

    #[tokio::test]
    async fn the_name_is_asked_of_the_upstreams_not_the_system() {
        // Тот самый круг: системный резолвер к этому времени отвечает
        // подставными адресами из подсети тоннеля, и верить ему нельзя.
        let real: IpAddr = "45.150.33.10".parse().expect("адрес");
        let resolver = resolver(vec![Arc::new(Canned(Ok(answer("ndfl.online", real))))]);

        assert_eq!(
            resolver.resolve("ndfl.online").await.expect("разрешилось"),
            [real]
        );
    }

    #[tokio::test]
    async fn a_silent_upstream_is_not_the_end() {
        // Список апстримов — запасные пути друг для друга; на первом же
        // молчании сдаваться нельзя.
        let real: IpAddr = "45.150.33.10".parse().expect("адрес");
        let resolver = resolver(vec![
            Arc::new(Canned(Err(DnsError::Upstream("молчит".to_owned())))),
            Arc::new(Canned(Ok(answer("ndfl.online", real)))),
        ]);

        assert_eq!(
            resolver.resolve("ndfl.online").await.expect("разрешилось"),
            [real]
        );
    }

    #[tokio::test]
    async fn nobody_answering_is_an_error_not_an_empty_list() {
        // Пустой список означал бы «такого имени нет», и клиент сказал бы
        // человеку не то: имя есть, спросить некого.
        //
        // Имя заведомо несуществующее: запасной путь спросит о нём систему, и
        // та тоже не назовёт адреса.
        let resolver = guarded(vec![Arc::new(Canned(Err(DnsError::Upstream(
            "молчит".to_owned(),
        ))))]);
        assert!(resolver.resolve("такого-имени-нет.invalid").await.is_err());
    }

    #[test]
    fn a_fake_address_is_never_taken_for_an_answer() {
        // Запасной путь спрашивает систему, а она может быть подменена нами
        // же. Поверить её ответу — значит позвонить самому себе, и это ровно
        // тот круг, ради выхода из которого всё это написано.
        let resolver = guarded(Vec::new());

        assert!(resolver.is_fake("198.18.0.13".parse().expect("адрес")));
        assert!(!resolver.is_fake("45.150.33.10".parse().expect("адрес")));
    }

    #[test]
    fn without_a_known_range_nothing_is_rejected() {
        // Подсеть могла не разобраться. Отвергать тогда всё подряд значило бы
        // остаться вовсе без разрешения имён.
        let resolver = resolver(Vec::new());
        assert!(!resolver.is_fake("198.18.0.13".parse().expect("адрес")));
    }
}
