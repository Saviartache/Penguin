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

/// Фичи, включённые в эту сборку, через запятую.
///
/// Считает `build.rs` по переменным Cargo — то есть по тому, что на самом
/// деле включено, а не по списку, который можно забыть пополнить. Ради этого
/// он и заведён: см. тест `every_enabled_feature_brings_its_protocols`.
pub const FEATURES: &str = env!("PENGUIN_FEATURES");

/// Что каждая фича обязана положить в реестр.
///
/// Оракул для тестов ниже, и потому `cfg(test)`: в работе программе это знание
/// не нужно — она спрашивает реестр. Нужно оно проверке, и забыть здесь так же
/// нельзя, как забыть строку регистрации: тест смотрит в обе стороны — и что
/// объявленное зарегистрировано, и что зарегистрированное объявлено.
///
/// `None` — фича не про протоколы (`default`) либо про протокол, о котором
/// здесь не написали. Второе тест считает ошибкой.
#[cfg(test)]
fn protocols_of(feature: &str) -> Option<&'static [&'static str]> {
    Some(match feature {
        // Не протокол: перечисление остальных.
        "default" => &[],
        "hysteria2" => &["hysteria2"],
        "trojan" => &["trojan"],
        "shadowsocks" => &["shadowsocks"],
        "vless" => &["vless"],
        "tuic" => &["tuic"],
        "anytls" => &["anytls"],
        "juicity" => &["juicity"],
        "snell" => &["snell"],
        "gost-relay" => &["gost-relay"],
        // Одна фича, два имени: с TLS и без.
        "socks5" => &["socks5", "socks5-tls"],
        // Одна фича, два имени в настройках.
        "http-proxy" => &["http", "https"],
        _ => return None,
    })
}

/// Регистрирует протоколы, включённые в сборку.
///
/// Добавление протокола — одна строка здесь, одна фича в `Cargo.toml` и одна
/// строка в [`protocols_of`]. Больше нигде в программе трогать ничего не нужно.
fn register_protocols(registry: &mut ProtocolRegistry) {
    #[cfg(feature = "hysteria2")]
    registry.register(Arc::new(penguin_hysteria2::Hysteria2Factory::new()));

    #[cfg(feature = "trojan")]
    registry.register(Arc::new(penguin_trojan::TrojanFactory::new()));

    #[cfg(feature = "shadowsocks")]
    registry.register(Arc::new(penguin_shadowsocks::ShadowsocksFactory::new()));

    #[cfg(feature = "vless")]
    registry.register(Arc::new(penguin_vless::VlessFactory::new()));

    #[cfg(feature = "tuic")]
    registry.register(Arc::new(penguin_tuic::TuicFactory::new()));

    #[cfg(feature = "anytls")]
    registry.register(Arc::new(penguin_anytls::AnyTlsFactory::new()));

    #[cfg(feature = "juicity")]
    registry.register(Arc::new(penguin_juicity::JuicityFactory::new()));

    #[cfg(feature = "snell")]
    registry.register(Arc::new(penguin_snell::SnellFactory::new()));

    #[cfg(feature = "gost-relay")]
    registry.register(Arc::new(penguin_gost_relay::GostRelayFactory::new()));

    // Две записи из одного крейта: `socks5` и `socks5-tls`. Под TLS не видны
    // ни имя сервера назначения, ни пароль — а без TLS видно и то и другое.
    #[cfg(feature = "socks5")]
    {
        registry.register(Arc::new(penguin_socks5::Socks5Factory::new()));
        registry.register(Arc::new(penguin_socks5::Socks5Factory::tls()));
    }

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

    /// Фичи этой сборки, кроме служебных.
    fn enabled_features() -> Vec<&'static str> {
        FEATURES
            .split(',')
            .filter(|name| !name.is_empty())
            .collect()
    }

    // Своего теста «протокол зарегистрирован» у протоколов нет намеренно:
    // два теста ниже покрывают их все сразу и по построению не могут отстать
    // от списка. Двадцать шесть одинаковых тестов — это двадцать шесть
    // поводов забыть двадцать седьмой.
    #[test]
    fn every_enabled_feature_brings_its_protocols() {
        // Главная ошибка при добавлении протокола: фича есть, зависимость
        // подключилась, крейт собрался — а строку регистрации забыли.
        // Собирается такое молча, а находится профилем «неизвестный протокол»
        // у человека, который ничего не менял.
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
        // Обратная сторона: протокол, зарегистрированный мимо фичи, нельзя ни
        // выключить, ни найти по имени фичи — и `--no-default-features`
        // соберёт демона с ним внутри.
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
