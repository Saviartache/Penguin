//! Пул активных исходящих: по одному на профиль, общие для всех соединений.
//!
//! Здесь же — **единственное место во всей программе, где перечислены
//! протоколы**. Ни `router`, ни `netstack`, ни `gui` не содержат ни одной
//! строки, знающей слово «hysteria»; добавление второго протокола — это новая
//! фича в `Cargo.toml` и одна строка регистрации ниже.
//!
//! Направление создаётся один раз на профиль и живёт, пока профиль активен.
//! Пересоздавать его на каждое соединение значило бы платить рукопожатием
//! QUIC за каждую вкладку браузера.

use std::sync::Arc;

use dashmap::DashMap;
use penguin_config::schema::profile::Profile;
use penguin_core::id::OutboundId;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::BuildContext;
use penguin_proto::outbound::Outbound;
use penguin_proto::registry::ProtocolRegistry;
use tokio::sync::Mutex;

use crate::direct::DirectOutbound;

/// Пул исходящих направлений.
pub struct OutboundPool {
    registry: ProtocolRegistry,
    dialer: Arc<dyn Dialer>,
    active: DashMap<OutboundId, Arc<dyn Outbound>>,
    /// Замок на создание: два одновременных соединения к одному профилю не
    /// должны поднять два соединения QUIC.
    building: Mutex<()>,
}

impl std::fmt::Debug for OutboundPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundPool")
            .field("protocols", &self.registry.protocols().collect::<Vec<_>>())
            .field("active", &self.active.len())
            .finish()
    }
}

impl OutboundPool {
    /// Создаёт пул со всеми протоколами, включёнными в сборку.
    pub fn new(dialer: Arc<dyn Dialer>) -> Self {
        let mut registry = ProtocolRegistry::new();
        register_protocols(&mut registry);

        let pool = Self {
            registry,
            dialer: Arc::clone(&dialer),
            active: DashMap::new(),
            building: Mutex::new(()),
        };

        // Прямой выход — такое же направление, как любое другое. Благодаря
        // этому у движка нет отдельной ветки «а если напрямую»: решение
        // маршрутизатора всегда превращается в поиск направления по имени.
        pool.active
            .insert(OutboundId::direct(), Arc::new(DirectOutbound::new(dialer)));
        pool
    }

    /// Имена протоколов, доступных в этой сборке.
    pub fn protocols(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.registry.protocols().collect();
        names.sort_unstable();
        names
    }

    /// Проверяет параметры профиля, не подключаясь.
    ///
    /// Через общую точку входа реестра: протокол может работать на потоках
    /// или на пакетах, и ошибку в поле интерфейс показывает одинаково.
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

        if let Some(existing) = self.active.get(&id) {
            return Ok(Arc::clone(&existing));
        }

        // Замок держится на время подключения: без него десяток соединений,
        // стартовавших разом, поднял бы десяток соединений QUIC.
        let _guard = self.building.lock().await;

        // Пока ждали замок, направление мог создать кто-то другой.
        if let Some(existing) = self.active.get(&id) {
            return Ok(Arc::clone(&existing));
        }

        let factory = self.registry.get(&profile.outbound.protocol)?;
        let ctx = BuildContext {
            id: id.clone(),
            dialer: Arc::clone(&self.dialer),
        };
        let outbound = factory.build(ctx, &profile.outbound.params).await?;

        tracing::info!(
            profile = %profile.id,
            protocol = profile.outbound.protocol,
            "направление поднято"
        );
        self.active.insert(id, Arc::clone(&outbound));
        Ok(outbound)
    }

    /// Направление по идентификатору, если оно уже поднято.
    pub fn get(&self, id: &OutboundId) -> Option<Arc<dyn Outbound>> {
        self.active.get(id).map(|entry| Arc::clone(&entry))
    }

    /// Прямой выход.
    ///
    /// Есть всегда: он создаётся вместе с пулом и не требует подключения.
    pub fn direct(&self) -> Arc<dyn Outbound> {
        self.active
            .get(&OutboundId::direct())
            .map(|entry| Arc::clone(&entry))
            .unwrap_or_else(|| Arc::new(DirectOutbound::new(Arc::clone(&self.dialer))))
    }

    /// Закрывает направление профиля.
    pub async fn close(&self, id: &OutboundId) {
        if id.is_direct() {
            return;
        }
        if let Some((_, outbound)) = self.active.remove(id)
            && let Err(err) = outbound.close().await
        {
            tracing::debug!(%id, %err, "направление закрылось с ошибкой");
        }
    }

    /// Закрывает все направления, кроме прямого выхода.
    pub async fn close_all(&self) {
        let ids: Vec<OutboundId> = self
            .active
            .iter()
            .map(|e| e.key().clone())
            .filter(|id| !id.is_direct())
            .collect();
        for id in ids {
            self.close(&id).await;
        }
    }
}

/// Регистрирует протоколы, включённые в сборку.
///
/// Добавление протокола — одна строка здесь и одна фича в `Cargo.toml`.
/// Больше нигде в программе трогать ничего не нужно.
fn register_protocols(registry: &mut ProtocolRegistry) {
    #[cfg(feature = "hysteria2")]
    registry.register(Arc::new(penguin_hysteria2::Hysteria2Factory::new()));

    #[cfg(feature = "socks5")]
    registry.register(Arc::new(penguin_socks5::Socks5Factory::new()));

    // Две записи из одного крейта: `http` и `https` отличаются одной строкой
    // настройки, но именами в конфигурации — двумя. Разница между ними —
    // это разница между «пароль уходит открытым текстом» и «не уходит», и
    // прятать её в поле внутри профиля значит прятать не то.
    #[cfg(feature = "http-proxy")]
    {
        registry.register(Arc::new(penguin_http_proxy::HttpProxyFactory::http()));
        registry.register(Arc::new(penguin_http_proxy::HttpProxyFactory::https()));
    }

    let _ = registry;
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::outbound::RawOutbound;
    use penguin_dns::resolver::SystemResolver;
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

    #[cfg(feature = "hysteria2")]
    #[test]
    fn hysteria2_is_registered() {
        assert!(pool().protocols().contains(&"hysteria2"));
    }

    #[cfg(feature = "socks5")]
    #[test]
    fn socks5_is_registered() {
        assert!(pool().protocols().contains(&"socks5"));
    }

    #[cfg(feature = "http-proxy")]
    #[test]
    fn both_http_proxies_are_registered() {
        // Имена разные, крейт один: реестр обязан знать оба, иначе профиль
        // `https` в файле настроек окажется профилем неизвестного протокола.
        let protocols = pool().protocols();
        assert!(protocols.contains(&"http"));
        assert!(protocols.contains(&"https"));
    }

    #[cfg(feature = "socks5")]
    #[test]
    fn a_proxy_profile_is_checked_without_network() {
        // Ошибку в поле интерфейс обязан показать сразу, а не через минуту
        // неудачного подключения.
        let pool = pool();
        assert!(
            pool.validate(&profile("socks5", json!({ "server": "127.0.0.1" })))
                .is_err(),
            "адрес без порта обязан быть отвергнут"
        );
        pool.validate(&profile("socks5", json!({ "server": "127.0.0.1:1080" })))
            .expect("настройки верны");
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
        // Ошибку в поле интерфейс обязан показать сразу, а не через минуту
        // неудачного подключения.
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

    #[tokio::test]
    async fn direct_survives_close_all() {
        // Прямой выход не поднимается и не опускается: он нужен всегда, в том
        // числе чтобы выпустить трафик после отключения тоннеля.
        let pool = pool();
        pool.close_all().await;
        assert!(pool.get(&OutboundId::direct()).is_some());
    }
}
