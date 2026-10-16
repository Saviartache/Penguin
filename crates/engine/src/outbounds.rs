//! Пул активных исходящих: по одному на профиль, общие для всех соединений.
//!
//! Единственное место, где перечислены протоколы (AGENTS §8).

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use penguin_config::schema::profile::Profile;
use penguin_core::id::OutboundId;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::BuildContext;
use penguin_proto::outbound::Outbound;
use penguin_proto::registry::ProtocolRegistry;
use tokio::sync::Mutex;

use crate::direct::DirectOutbound;
use crate::packet_tunnel::PacketTunnel;

/// Пул исходящих направлений.
pub struct OutboundPool {
    registry: ProtocolRegistry,
    dialer: Arc<dyn Dialer>,
    active: RwLock<HashMap<OutboundId, Arc<dyn Outbound>>>,
    /// Профили поднятых направлений: по ним пересоздаётся умершее.
    profiles: RwLock<HashMap<OutboundId, Profile>>,
    /// Не даёт двум соединениям к одному профилю поднять два QUIC.
    building: Mutex<()>,
}

impl std::fmt::Debug for OutboundPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundPool")
            .field("protocols", &self.registry.protocols().collect::<Vec<_>>())
            .field("active", &self.active.read().len())
            .finish()
    }
}

impl OutboundPool {
    /// Создаёт пул со всеми протоколами, включёнными в сборку.
    pub fn new(dialer: Arc<dyn Dialer>) -> Self {
        let mut registry = ProtocolRegistry::new();
        register_protocols(&mut registry);

        // Прямой выход — обычное направление: отдельной ветки в движке нет.
        let direct: Arc<dyn Outbound> = Arc::new(DirectOutbound::new(Arc::clone(&dialer)));
        Self {
            registry,
            dialer,
            active: RwLock::new(HashMap::from([(OutboundId::direct(), direct)])),
            profiles: RwLock::default(),
            building: Mutex::new(()),
        }
    }

    /// Имена протоколов, доступных в этой сборке.
    pub fn protocols(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.registry.protocols().collect();
        names.sort_unstable();
        names
    }

    /// Проверяет параметры профиля, не подключаясь.
    pub fn validate(&self, profile: &Profile) -> Result<(), ProtocolError> {
        self.registry
            .validate(&profile.outbound.protocol, &profile.outbound.params)
    }

    /// Направление профиля: из пула или свежесозданное.
    pub async fn get_or_connect(
        &self,
        profile: &Profile,
    ) -> Result<Arc<dyn Outbound>, ProtocolError> {
        let id = OutboundId::from(profile.id.clone());
        if let Some(existing) = self.get(&id) {
            return Ok(existing);
        }

        let _guard = self.building.lock().await;
        // Пока ждали замок, направление мог создать другой.
        if let Some(existing) = self.get(&id) {
            return Ok(existing);
        }

        self.build(profile).await
    }

    /// Живое направление: умершее соединение пересоздаётся по тому же профилю.
    ///
    /// Без этого после обрыва (сон, смена сети, перезапуск сервера) тоннель
    /// оставался «подключённым», но не пропускал ни одного соединения.
    pub async fn revive(
        &self,
        outbound: Arc<dyn Outbound>,
    ) -> Result<Arc<dyn Outbound>, ProtocolError> {
        if outbound.is_alive() {
            return Ok(outbound);
        }

        let id = outbound.id();
        let _guard = self.building.lock().await;
        // Пока ждали замок, направление мог пересоздать другой.
        if let Some(current) = self.get(&id)
            && current.is_alive()
        {
            return Ok(current);
        }

        let Some(profile) = self.profiles.read().get(&id).cloned() else {
            return Err(ProtocolError::Disconnected(format!(
                "направление `{id}` закрыто"
            )));
        };

        tracing::info!(%id, "соединение с сервером потеряно — поднимаю заново");
        let fresh = self.build(&profile).await?;
        if let Err(err) = outbound.close().await {
            tracing::debug!(%id, %err, "умершее направление закрылось с ошибкой");
        }
        Ok(fresh)
    }

    /// Строит направление и кладёт в пул; вызывается под замком `building`.
    async fn build(&self, profile: &Profile) -> Result<Arc<dyn Outbound>, ProtocolError> {
        let id = OutboundId::from(profile.id.clone());
        let ctx = BuildContext {
            id: id.clone(),
            dialer: Arc::clone(&self.dialer),
        };

        // Пакетный протокол приезжает в мосте и неотличим от обычного.
        let outbound: Arc<dyn Outbound> =
            if let Some(packets) = self.registry.get_packet(&profile.outbound.protocol) {
                let tunnel = packets.build(ctx, &profile.outbound.params).await?;
                Arc::new(PacketTunnel::new(tunnel))
            } else {
                let factory = self.registry.get(&profile.outbound.protocol)?;
                factory.build(ctx, &profile.outbound.params).await?
            };

        tracing::info!(
            profile = %profile.id,
            protocol = profile.outbound.protocol,
            "направление поднято"
        );
        self.profiles.write().insert(id.clone(), profile.clone());
        self.active.write().insert(id, Arc::clone(&outbound));
        Ok(outbound)
    }

    /// Направление по идентификатору, если оно уже поднято.
    pub fn get(&self, id: &OutboundId) -> Option<Arc<dyn Outbound>> {
        self.active.read().get(id).cloned()
    }

    /// Прямой выход: есть всегда.
    pub fn direct(&self) -> Arc<dyn Outbound> {
        self.get(&OutboundId::direct())
            .unwrap_or_else(|| Arc::new(DirectOutbound::new(Arc::clone(&self.dialer))))
    }

    /// Закрывает направление профиля.
    pub async fn close(&self, id: &OutboundId) {
        if id.is_direct() {
            return;
        }
        // Ждёт идущую сборку: иначе пересозданное направление пережило бы отключение.
        let _guard = self.building.lock().await;
        self.profiles.write().remove(id);
        let removed = self.active.write().remove(id);
        if let Some(outbound) = removed
            && let Err(err) = outbound.close().await
        {
            tracing::debug!(%id, %err, "направление закрылось с ошибкой");
        }
    }

    /// Закрывает все направления, кроме прямого выхода.
    pub async fn close_all(&self) {
        let ids: Vec<OutboundId> = self
            .active
            .read()
            .keys()
            .filter(|id| !id.is_direct())
            .cloned()
            .collect();
        for id in ids {
            self.close(&id).await;
        }
    }
}

/// Фичи, включённые в эту сборку, через запятую (считает `build.rs`).
pub const FEATURES: &str = env!("PENGUIN_FEATURES");

/// Что каждая фича обязана положить в реестр; `None` — фича не описана.
#[cfg(test)]
fn protocols_of(feature: &str) -> Option<&'static [&'static str]> {
    Some(match feature {
        "default" => &[],
        "pingwin" => &["pingwin"],
        "dpi" => &["dpi"],
        "hysteria2" => &["hysteria2"],
        "trojan" => &["trojan"],
        "shadowsocks" => &["shadowsocks"],
        "vless" => &["vless"],
        "vmess" => &["vmess"],
        "tuic" => &["tuic"],
        "anytls" => &["anytls"],
        "juicity" => &["juicity"],
        "naive" => &["http2", "http3"],
        "masque" => &["masque", "masque-ip"],
        "wireguard" => &["wireguard"],
        "trusttunnel" => &["trusttunnel"],
        "socks5" => &["socks5", "socks5-tls"],
        _ => return None,
    })
}

/// Регистрирует протоколы, включённые в сборку: строка здесь, фича в
/// `Cargo.toml`, строка в [`protocols_of`].
fn register_protocols(registry: &mut ProtocolRegistry) {
    #[cfg(feature = "pingwin")]
    registry.register(Arc::new(penguin_pingwin::PingwinFactory::new()));

    #[cfg(feature = "dpi")]
    registry.register(Arc::new(penguin_dpi::DpiFactory::new()));

    #[cfg(feature = "hysteria2")]
    registry.register(Arc::new(penguin_hysteria2::Hysteria2Factory::new()));

    #[cfg(feature = "trojan")]
    registry.register(Arc::new(penguin_trojan::TrojanFactory::new()));

    #[cfg(feature = "shadowsocks")]
    registry.register(Arc::new(penguin_shadowsocks::ShadowsocksFactory::new()));

    #[cfg(feature = "vless")]
    registry.register(Arc::new(penguin_vless::VlessFactory::new()));

    #[cfg(feature = "vmess")]
    registry.register(Arc::new(penguin_vmess::VmessFactory::new()));

    #[cfg(feature = "tuic")]
    registry.register(Arc::new(penguin_tuic::TuicFactory::new()));

    #[cfg(feature = "anytls")]
    registry.register(Arc::new(penguin_anytls::AnyTlsFactory::new()));

    #[cfg(feature = "juicity")]
    registry.register(Arc::new(penguin_juicity::JuicityFactory::new()));

    // Пакетные протоколы — вторая таблица реестра.
    #[cfg(feature = "wireguard")]
    registry.register_packet(Arc::new(penguin_wireguard::WireguardFactory::new()));

    #[cfg(feature = "trusttunnel")]
    registry.register(Arc::new(penguin_trusttunnel::TrustTunnelFactory::new()));

    #[cfg(feature = "masque")]
    registry.register(Arc::new(penguin_masque::MasqueFactory::new()));
    // RFC 9484 (`CONNECT-IP`): пакеты, а не датаграммы.
    #[cfg(feature = "masque")]
    registry.register_packet(Arc::new(penguin_masque::MasqueIpFactory::new()));

    #[cfg(feature = "naive")]
    {
        registry.register(Arc::new(penguin_naive::NaiveFactory::http2()));
        registry.register(Arc::new(penguin_naive::NaiveFactory::http3()));
    }

    #[cfg(feature = "socks5")]
    {
        registry.register(Arc::new(penguin_socks5::Socks5Factory::new()));
        registry.register(Arc::new(penguin_socks5::Socks5Factory::tls()));
    }

    let _ = registry;
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use penguin_config::schema::outbound::RawOutbound;
    use penguin_core::address::SocketAddress;
    use penguin_core::id::ProfileId;
    use penguin_dns::resolver::SystemResolver;
    use penguin_proto::capabilities::Capabilities;
    use penguin_proto::datagram::ProxyDatagram;
    use penguin_proto::factory::ProtocolFactory;
    use penguin_proto::stream::ProxyStream;
    use serde_json::json;

    use super::*;
    use crate::direct::SystemDialer;

    fn pool() -> OutboundPool {
        OutboundPool::new(Arc::new(SystemDialer::new(Arc::new(SystemResolver))))
    }

    fn profile(protocol: &str, params: serde_json::Value) -> Profile {
        Profile::new("home", "Домашний", RawOutbound::new(protocol, params))
    }

    #[test]
    fn direct_is_always_available() {
        let pool = pool();
        assert_eq!(pool.direct().protocol(), "direct");
        assert!(pool.get(&OutboundId::direct()).is_some());
    }

    #[cfg(feature = "socks5")]
    #[test]
    fn a_proxy_profile_is_checked_without_network() {
        let pool = pool();
        assert!(
            pool.validate(&profile("socks5", json!({ "server": "127.0.0.1" })))
                .is_err(),
            "адрес без порта обязан быть отвергнут"
        );
        pool.validate(&profile("socks5", json!({ "server": "127.0.0.1:1080" })))
            .expect("настройки верны");
    }

    fn enabled_features() -> Vec<&'static str> {
        FEATURES
            .split(',')
            .filter(|name| !name.is_empty())
            .collect()
    }

    // Два теста ниже покрывают все протоколы сразу и не отстают от списка.
    #[test]
    fn every_enabled_feature_brings_its_protocols() {
        let registered = pool().protocols();

        for feature in enabled_features() {
            let expected = protocols_of(feature).unwrap_or_else(|| {
                panic!(
                    "фича `{feature}` включена, а что она даёт — нигде не сказано:                      допишите её в `protocols_of`"
                )
            });
            for protocol in expected {
                assert!(
                    registered.contains(protocol),
                    "фича `{feature}` включена, а протокола `{protocol}` в реестре нет"
                );
            }
        }
    }

    #[test]
    fn every_registered_protocol_comes_from_an_enabled_feature() {
        let announced: Vec<&str> = enabled_features()
            .into_iter()
            .filter_map(protocols_of)
            .flatten()
            .copied()
            .collect();

        for protocol in pool().protocols() {
            assert!(
                announced.contains(&protocol),
                "`{protocol}` в реестре есть, а фичи, которая его даёт, нет"
            );
        }
    }

    #[test]
    fn unknown_protocol_is_rejected_by_name() {
        let err = pool()
            .validate(&profile("телепатия", json!({})))
            .expect_err("такого протокола нет");
        assert!(err.to_string().contains("телепатия"));
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn validation_happens_without_network() {
        let pool = pool();
        assert!(
            pool.validate(&profile(
                "hysteria2",
                json!({ "server": "example.com:443" })
            ))
            .is_err()
        );
        pool.validate(&profile(
            "hysteria2",
            json!({ "server": "example.com:443", "auth": "secret" }),
        ))
        .expect("настройки верны");
    }

    /// Протокол, чьё соединение умирает по команде теста.
    struct Mortal {
        builds: AtomicUsize,
        alive: Arc<AtomicBool>,
    }

    struct MortalOutbound {
        alive: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl ProtocolFactory for Mortal {
        fn protocol(&self) -> &'static str {
            "mortal"
        }

        fn validate(&self, _params: &serde_json::Value) -> Result<(), ProtocolError> {
            Ok(())
        }

        async fn build(
            &self,
            _ctx: BuildContext,
            _params: &serde_json::Value,
        ) -> Result<Arc<dyn Outbound>, ProtocolError> {
            self.builds.fetch_add(1, Ordering::SeqCst);
            self.alive.store(true, Ordering::SeqCst);
            Ok(Arc::new(MortalOutbound {
                alive: Arc::clone(&self.alive),
            }))
        }
    }

    #[async_trait::async_trait]
    impl Outbound for MortalOutbound {
        fn id(&self) -> OutboundId {
            OutboundId::from(ProfileId::new("home"))
        }

        fn protocol(&self) -> &'static str {
            "mortal"
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities::default()
        }

        async fn connect_tcp(
            &self,
            _target: &SocketAddress,
        ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
            Err(ProtocolError::Unsupported("TCP"))
        }

        async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
            Err(ProtocolError::Unsupported("UDP"))
        }

        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::SeqCst)
        }
    }

    fn mortal_pool() -> (OutboundPool, Arc<Mortal>) {
        let mut pool = pool();
        let mortal = Arc::new(Mortal {
            builds: AtomicUsize::new(0),
            alive: Arc::new(AtomicBool::new(true)),
        });
        pool.registry.register(Arc::clone(&mortal) as _);
        (pool, mortal)
    }

    #[tokio::test]
    async fn a_dead_connection_is_rebuilt_from_its_profile() {
        let (pool, mortal) = mortal_pool();
        let first = pool
            .get_or_connect(&profile("mortal", json!({})))
            .await
            .expect("поднимается");

        let same = pool.revive(Arc::clone(&first)).await.expect("живо");
        assert_eq!(mortal.builds.load(Ordering::SeqCst), 1, "живое не трогаем");
        assert!(same.is_alive());

        mortal.alive.store(false, Ordering::SeqCst);
        let fresh = pool.revive(first).await.expect("пересоздаётся");
        assert_eq!(mortal.builds.load(Ordering::SeqCst), 2);
        assert!(fresh.is_alive());
        assert!(pool.get(&fresh.id()).expect("в пуле").is_alive());
    }

    #[tokio::test]
    async fn a_closed_profile_is_not_rebuilt() {
        let (pool, mortal) = mortal_pool();
        let outbound = pool
            .get_or_connect(&profile("mortal", json!({})))
            .await
            .expect("поднимается");
        pool.close_all().await;

        mortal.alive.store(false, Ordering::SeqCst);
        let err = pool.revive(outbound).await.err().expect("профиль закрыт");
        assert!(matches!(err, ProtocolError::Disconnected(_)));
        assert_eq!(mortal.builds.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn direct_survives_close_all() {
        let pool = pool();
        pool.close_all().await;
        assert!(pool.get(&OutboundId::direct()).is_some());
    }
}
