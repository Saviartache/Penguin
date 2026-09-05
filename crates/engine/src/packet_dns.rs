//! Разрешение имён **внутри** пакетного тоннеля.
//!
//! Через направление уровня пакетов ходят пакеты, а пакету нужен адрес.
//! Приложение же приходит с именем. Разрешить его надо тем же путём, каким
//! пойдут данные: спросить снаружи — значит отдать провайдеру список имён,
//! которые человек спрашивает, ровно то, от чего он тоннель и поднял.
//!
//! ```text
//!   имя ──► запрос DNS ──► тот же тоннель ──► сервер имён, который дал сервер
//!   адрес ◄──────────────────────────────────────────────────────── ответ
//! ```
//!
//! # Почему запрос уходит по своему каналу
//!
//! Канал датаграмм у тоннеля выдаётся на сессию, и ответы в нём приходят
//! вперемешку с чужими только если сессию делить. Поэтому под каждый запрос
//! берётся свой канал: иначе ответ сервера имён достался бы приложению,
//! которое его не спрашивало.
//!
//! # Чего здесь нет
//!
//! Ни DNSSEC, ни повторов по TCP при усечённом ответе, ни отрицательного
//! кэша. Усечённый ответ (`TC`) для запроса адреса — редкость: адреса
//! помещаются в датаграмму. Всё это заводится тогда, когда понадобится, а не
//! на всякий случай.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hickory_proto::rr::RecordType;
use penguin_core::address::{Address, SocketAddress};
use penguin_dns::message;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;

/// Порт сервера имён.
const DNS_PORT: u16 = 53;

/// Сколько ждать ответа от одного сервера имён.
///
/// Внутри тоннеля путь длиннее обычного, но не настолько: три секунды — это
/// уже «сервер молчит», и лучше спросить следующего, чем ждать дальше.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Наименьший срок жизни записи в кэше.
///
/// Сервер вправе прислать `TTL 0`, и честно перепрашивать его на каждое
/// соединение значило бы платить оборотом по тоннелю за каждую картинку на
/// странице.
const MIN_TTL: Duration = Duration::from_secs(10);

/// Наибольший срок.
///
/// Держать дольше нельзя: адрес за именем меняется, а переподключение
/// профиля кэш не чистит.
const MAX_TTL: Duration = Duration::from_secs(3600);

/// Запомненный ответ.
#[derive(Debug, Clone)]
struct Cached {
    addresses: Vec<IpAddr>,
    until: Instant,
}

/// Кто разрешает имена внутри тоннеля.
#[derive(Debug)]
pub struct TunnelResolver {
    /// Серверы имён, которые назвал сервер тоннеля.
    servers: Vec<IpAddr>,
    cache: DashMap<String, Cached>,
}

impl TunnelResolver {
    /// Заводит резолвер на списке серверов имён.
    pub fn new(servers: Vec<IpAddr>) -> Self {
        Self {
            servers,
            cache: DashMap::new(),
        }
    }

    /// Умеет ли он вообще что-нибудь разрешить.
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Готовый адрес из кэша, если он ещё не протух.
    pub fn cached(&self, name: &str) -> Option<IpAddr> {
        let entry = self.cache.get(name)?;
        if entry.until <= Instant::now() {
            return None;
        }
        entry.addresses.first().copied()
    }

    /// Спрашивает серверы имён по очереди, пока кто-нибудь не ответит.
    ///
    /// Канал берётся заново на каждый вызов: он же и есть та сессия, по
    /// которой придёт ответ.
    pub async fn resolve(
        &self,
        name: &str,
        channel: &dyn ProxyDatagram,
        id: u16,
    ) -> Result<IpAddr, ProtocolError> {
        if let Some(address) = self.cached(name) {
            return Ok(address);
        }
        if self.servers.is_empty() {
            return Err(no_servers(name));
        }

        let mut last: Option<ProtocolError> = None;
        for server in &self.servers {
            match self.ask(name, *server, channel, id).await {
                Ok(address) => return Ok(address),
                Err(err) => {
                    tracing::debug!(%server, %name, %err, "сервер имён не ответил");
                    last = Some(err);
                }
            }
        }

        Err(last.unwrap_or_else(|| no_servers(name)))
    }

    /// Один запрос к одному серверу.
    async fn ask(
        &self,
        name: &str,
        server: IpAddr,
        channel: &dyn ProxyDatagram,
        id: u16,
    ) -> Result<IpAddr, ProtocolError> {
        let query = message::build_query(name, RecordType::A, id)
            .map_err(|e| ProtocolError::InvalidConfig(format!("запрос DNS не собрался: {e}")))?;

        let target = SocketAddress::new(Address::Ip(server), DNS_PORT);
        channel.send_to(query.into(), &target).await?;

        // Чужие датаграммы на этом канале взяться неоткуда — он свой на
        // запрос, — но ответ не с тем номером означает, что кто-то отвечает
        // не на наш вопрос. Ждём свой, пока не истечёт срок.
        let deadline = Instant::now() + QUERY_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(ProtocolError::Unreachable(format!(
                    "сервер имён {server} молчит про `{name}`"
                )));
            }

            let (payload, _) = tokio::time::timeout(left, channel.recv_from())
                .await
                .map_err(|_| {
                    ProtocolError::Unreachable(format!("сервер имён {server} молчит про `{name}`"))
                })??;

            if !answers_query(&payload, id) {
                continue;
            }

            let addresses = message::extract_addresses(&payload).map_err(|e| {
                ProtocolError::Unreachable(format!("сервер имён не назвал адрес `{name}`: {e}"))
            })?;
            let Some(first) = addresses.first().copied() else {
                return Err(ProtocolError::Unreachable(format!(
                    "у имени `{name}` нет адреса"
                )));
            };

            let ttl = message::min_ttl(&payload)
                .map_or(MIN_TTL, |ttl| Duration::from_secs(u64::from(ttl)))
                .clamp(MIN_TTL, MAX_TTL);
            self.cache.insert(
                name.to_owned(),
                Cached {
                    addresses,
                    until: Instant::now() + ttl,
                },
            );
            return Ok(first);
        }
    }
}

/// Тот ли это ответ, которого ждали.
///
/// Номер стоит в первых двух байтах и приходит обратно как есть. Совпадения
/// мало для подлинности, но несовпадение — верный признак чужого ответа, и
/// принять такой значило бы соединиться не туда.
fn answers_query(datagram: &[u8], id: u16) -> bool {
    datagram.len() >= 2 && u16::from_be_bytes([datagram[0], datagram[1]]) == id
}

/// Имён разрешать нечем.
///
/// Не `Unsupported`: тот несёт только постоянную строку, а имя в сообщении и
/// есть самое полезное. `InvalidConfig` при этом не повторяется — и верно:
/// сервера имён от повтора не появится.
fn no_servers(name: &str) -> ProtocolError {
    ProtocolError::InvalidConfig(format!(
        "имя `{name}` разрешать нечем: тоннель не назвал ни одного сервера имён, \
         а спрашивать снаружи нельзя — это отдало бы список имён мимо тоннеля"
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use bytes::Bytes;

    use super::*;

    /// Канал, который отвечает заранее сложенным.
    struct Canned {
        answers: Mutex<Vec<Bytes>>,
        sent: Mutex<Vec<SocketAddress>>,
    }

    impl Canned {
        fn new(answers: Vec<Bytes>) -> Self {
            Self {
                answers: Mutex::new(answers),
                sent: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ProxyDatagram for Canned {
        async fn send_to(
            &self,
            _payload: Bytes,
            target: &SocketAddress,
        ) -> Result<(), ProtocolError> {
            self.sent.lock().expect("замок").push(target.clone());
            Ok(())
        }

        async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
            let next = {
                let mut answers = self.answers.lock().expect("замок");
                if answers.is_empty() {
                    None
                } else {
                    Some(answers.remove(0))
                }
            };
            match next {
                Some(payload) => Ok((
                    payload,
                    SocketAddress::new(Address::Ip("10.0.0.53".parse().expect("адрес")), DNS_PORT),
                )),
                // Ответов больше нет: ведём себя как молчащая сеть.
                None => std::future::pending().await,
            }
        }
    }

    /// Ответ сервера имён: один адрес A с заданным сроком.
    fn answer(id: u16, name: &str, address: &str, ttl: u32) -> Bytes {
        let question = message::build_query(name, RecordType::A, id).expect("запрос собирается");
        let parsed = message::parse_query(&question).expect("разбирается");
        let built = message::build_answer(&parsed, &[address.parse().expect("адрес")], ttl)
            .expect("ответ собирается");
        Bytes::from(built)
    }

    fn resolver() -> TunnelResolver {
        TunnelResolver::new(vec!["10.0.0.53".parse().expect("адрес")])
    }

    #[tokio::test]
    async fn a_name_is_resolved_through_the_tunnel() {
        let channel = Canned::new(vec![answer(7, "example.com", "93.184.216.34", 300)]);
        let address = resolver()
            .resolve("example.com", &channel, 7)
            .await
            .expect("разрешилось");

        assert_eq!(address, "93.184.216.34".parse::<IpAddr>().expect("адрес"));
        // Запрос ушёл серверу имён, который назвал тоннель, и на пятьдесят
        // третий порт.
        let sent = channel.sent.lock().expect("замок");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].port, DNS_PORT);
    }

    #[tokio::test]
    async fn an_answer_with_a_foreign_id_is_skipped_not_taken() {
        // Принять чужой ответ значило бы соединиться не туда.
        let channel = Canned::new(vec![
            answer(999, "example.com", "10.10.10.10", 300),
            answer(7, "example.com", "93.184.216.34", 300),
        ]);
        let address = resolver()
            .resolve("example.com", &channel, 7)
            .await
            .expect("разрешилось");
        assert_eq!(address, "93.184.216.34".parse::<IpAddr>().expect("адрес"));
    }

    #[tokio::test]
    async fn the_second_time_the_answer_comes_from_the_cache() {
        // Иначе каждая картинка на странице стоила бы оборота по тоннелю.
        let resolver = resolver();
        let channel = Canned::new(vec![answer(7, "example.com", "93.184.216.34", 300)]);
        resolver
            .resolve("example.com", &channel, 7)
            .await
            .expect("разрешилось");

        // Канал пуст: если бы резолвер спросил ещё раз, он бы завис.
        let address = resolver
            .resolve("example.com", &channel, 8)
            .await
            .expect("взялось из кэша");
        assert_eq!(address, "93.184.216.34".parse::<IpAddr>().expect("адрес"));
        assert_eq!(channel.sent.lock().expect("замок").len(), 1);
    }

    #[tokio::test]
    async fn a_tunnel_without_name_servers_says_so_instead_of_asking_outside() {
        // Спросить снаружи значило бы отдать имя мимо тоннеля.
        let resolver = TunnelResolver::new(Vec::new());
        assert!(resolver.is_empty());

        let channel = Canned::new(Vec::new());
        let error = resolver
            .resolve("example.com", &channel, 1)
            .await
            .expect_err("разрешать нечем");

        assert!(!error.is_retryable(), "повтор сервера имён не добавит");
        assert!(error.to_string().contains("example.com"), "{error}");
        assert!(
            channel.sent.lock().expect("замок").is_empty(),
            "запрос ушёл, хотя спрашивать некого"
        );
    }

    #[tokio::test]
    async fn a_silent_server_ends_with_an_error_not_a_hang() {
        let channel = Canned::new(Vec::new());
        let error = tokio::time::timeout(
            QUERY_TIMEOUT + Duration::from_secs(2),
            resolver().resolve("example.com", &channel, 7),
        )
        .await
        .expect("запрос повис")
        .expect_err("ответа не было");

        assert!(error.is_retryable(), "молчание стоит повторить");
    }

    #[test]
    fn a_short_datagram_is_not_mistaken_for_an_answer() {
        assert!(!answers_query(&[], 7));
        assert!(!answers_query(&[0], 7));
        assert!(answers_query(&[0, 7], 7));
    }

    #[test]
    fn the_cache_does_not_hold_a_name_forever() {
        // Адрес за именем меняется, а переподключение профиля кэш не чистит.
        assert!(MAX_TTL <= Duration::from_secs(3600));
        assert!(MIN_TTL > Duration::ZERO);
    }
}
