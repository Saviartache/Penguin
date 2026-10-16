//! Разрешение имён **внутри** пакетного тоннеля.
//!
//! Имя разрешается тем же путём, что и данные: спросить снаружи значит отдать
//! провайдеру список имён. Под каждый запрос берётся свой канал датаграмм, иначе
//! ответ достался бы чужому приложению.
//!
//! Нет DNSSEC, повторов по TCP при `TC` и отрицательного кэша.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use penguin_core::address::{Address, SocketAddress};
use penguin_dns::message::{self, RecordType};
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;

/// Порт сервера имён.
const DNS_PORT: u16 = 53;

/// Ожидание ответа от одного сервера имён: дольше — это уже молчание.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Наименьший срок записи: `TTL 0` не должен давать оборот по тоннелю на каждое соединение.
const MIN_TTL: Duration = Duration::from_secs(10);

/// Наибольший срок: переподключение профиля кэш не чистит, а адрес за именем меняется.
const MAX_TTL: Duration = Duration::from_secs(3600);

/// Предел записей кэша.
const MAX_CACHED: usize = 1024;

#[derive(Debug, Clone, Copy)]
struct Cached {
    address: IpAddr,
    until: Instant,
}

/// Кто разрешает имена внутри тоннеля.
#[derive(Debug)]
pub struct TunnelResolver {
    /// Серверы имён, названные сервером тоннеля.
    servers: Vec<IpAddr>,
    cache: RwLock<HashMap<String, Cached>>,
}

impl TunnelResolver {
    /// Заводит резолвер на списке серверов имён.
    pub fn new(servers: Vec<IpAddr>) -> Self {
        Self {
            servers,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Умеет ли он вообще что-нибудь разрешить.
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Адрес из кэша, если не протух.
    pub fn cached(&self, name: &str) -> Option<IpAddr> {
        let entry = *self.cache.read().get(name)?;
        (entry.until > Instant::now()).then_some(entry.address)
    }

    /// Спрашивает серверы имён по очереди, пока кто-нибудь не ответит.
    pub async fn resolve(
        &self,
        name: &str,
        channel: &dyn ProxyDatagram,
        id: u16,
    ) -> Result<IpAddr, ProtocolError> {
        if let Some(address) = self.cached(name) {
            return Ok(address);
        }

        let mut last = None;
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

    /// Один запрос к одному серверу; чужие по номеру ответы пропускаются до срока.
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

        let silent =
            || ProtocolError::Unreachable(format!("сервер имён {server} молчит про `{name}`"));
        let deadline = Instant::now() + QUERY_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let (payload, _) = tokio::time::timeout(left, channel.recv_from())
                .await
                .map_err(|_| silent())??;
            if !answers_query(&payload, id) {
                continue;
            }

            let addresses = message::extract_addresses(&payload).map_err(|e| {
                ProtocolError::Unreachable(format!("сервер имён не назвал адрес `{name}`: {e}"))
            })?;
            let Some(&address) = addresses.first() else {
                return Err(ProtocolError::Unreachable(format!(
                    "у имени `{name}` нет адреса"
                )));
            };

            let ttl = message::min_ttl(&payload)
                .map_or(MIN_TTL, |ttl| Duration::from_secs(u64::from(ttl)))
                .clamp(MIN_TTL, MAX_TTL);
            self.remember(name, address, ttl);
            return Ok(address);
        }
    }

    fn remember(&self, name: &str, address: IpAddr, ttl: Duration) {
        let now = Instant::now();
        let mut cache = self.cache.write();
        if cache.len() >= MAX_CACHED {
            cache.retain(|_, entry| entry.until > now);
            if cache.len() >= MAX_CACHED {
                cache.clear();
            }
        }
        cache.insert(
            name.to_owned(),
            Cached {
                address,
                until: now + ttl,
            },
        );
    }
}

/// Несовпадение номера — признак чужого ответа: принять его значит соединиться не туда.
fn answers_query(datagram: &[u8], id: u16) -> bool {
    datagram.len() >= 2 && u16::from_be_bytes([datagram[0], datagram[1]]) == id
}

/// Не `Unsupported`: имя в тексте полезнее; `InvalidConfig` не повторяется.
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
        let sent = channel.sent.lock().expect("замок");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].port, DNS_PORT);
    }

    #[tokio::test]
    async fn an_answer_with_a_foreign_id_is_skipped_not_taken() {
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
        let resolver = resolver();
        let channel = Canned::new(vec![answer(7, "example.com", "93.184.216.34", 300)]);
        resolver
            .resolve("example.com", &channel, 7)
            .await
            .expect("разрешилось");

        // Канал пуст: повторный запрос завис бы.
        let address = resolver
            .resolve("example.com", &channel, 8)
            .await
            .expect("взялось из кэша");
        assert_eq!(address, "93.184.216.34".parse::<IpAddr>().expect("адрес"));
        assert_eq!(channel.sent.lock().expect("замок").len(), 1);
    }

    #[tokio::test]
    async fn a_tunnel_without_name_servers_says_so_instead_of_asking_outside() {
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
        assert!(MAX_TTL <= Duration::from_secs(3600));
        assert!(MIN_TTL > Duration::ZERO);
    }

    #[test]
    fn the_cache_is_bounded() {
        let resolver = resolver();
        let address: IpAddr = "1.2.3.4".parse().expect("адрес");
        for step in 0..(MAX_CACHED * 2) {
            resolver.remember(&format!("host{step}.example"), address, MAX_TTL);
        }
        let len = resolver.cache.read().len();
        assert!(len <= MAX_CACHED, "кэш вырос до {len}");
    }
}
