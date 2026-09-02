//! `Router` — вычисление решения по контексту соединения.
//!
//! Порядок разбора целиком:
//!
//! ```text
//!   контекст соединения
//!         │
//!         ├─ кэш решений ──► попадание ──► готово
//!         │
//!         ├─ правила по порядку ──► первое совпавшее ──► готово
//!         │
//!         └─ умолчание режима
//! ```
//!
//! Набор правил лежит в [`arc_swap::ArcSwap`]: правки из интерфейса меняют
//! его целиком и мгновенно, не останавливая работу и не блокируя разбор
//! соединений. Читающая сторона при этом не платит ни одной блокировкой.

use arc_swap::ArcSwap;
use penguin_config::schema::routing::{RoutingConfig, TunnelMode};
use penguin_core::id::OutboundId;

use crate::cache::DecisionCache;
use crate::context::FlowContext;
use crate::decision::{Decision, ResolvedDecision, Verdict};
use crate::error::RouterResult;
use crate::ruleset::{CompileContext, RuleSet};

/// Маршрутизатор.
pub struct Router {
    rules: ArcSwap<RuleSet>,
    mode: ArcSwap<TunnelMode>,
    active: ArcSwap<OutboundId>,
    cache: DecisionCache,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("mode", &**self.mode.load())
            .field("rules", &self.rules.load().len())
            .field("active", &self.active.load().to_string())
            .finish()
    }
}

impl Router {
    /// Собирает маршрутизатор из настроек.
    pub fn new(
        config: &RoutingConfig,
        active: OutboundId,
        ctx: &CompileContext,
    ) -> RouterResult<Self> {
        Ok(Self {
            rules: ArcSwap::from_pointee(RuleSet::compile(config, ctx)?),
            mode: ArcSwap::from_pointee(config.mode),
            active: ArcSwap::from_pointee(active),
            cache: DecisionCache::new(),
        })
    }

    /// Маршрутизатор без правил: всё уходит по умолчанию режима.
    pub fn passthrough(mode: TunnelMode, active: OutboundId) -> Self {
        Self {
            rules: ArcSwap::from_pointee(RuleSet::empty()),
            mode: ArcSwap::from_pointee(mode),
            active: ArcSwap::from_pointee(active),
            cache: DecisionCache::new(),
        }
    }

    /// Заменяет набор правил на лету.
    pub fn replace_rules(&self, config: &RoutingConfig, ctx: &CompileContext) -> RouterResult<()> {
        let rules = RuleSet::compile(config, ctx)?;
        self.rules.store(std::sync::Arc::new(rules));
        self.mode.store(std::sync::Arc::new(config.mode));
        // Кэш обязан обнулиться: в нём лежат решения по прежним правилам.
        self.cache.clear();
        Ok(())
    }

    /// Меняет активный профиль.
    pub fn set_active(&self, active: OutboundId) {
        self.active.store(std::sync::Arc::new(active));
        // Решения `ActiveTunnel` в кэше указывают на прежний профиль.
        self.cache.clear();
    }

    /// Текущий режим.
    pub fn mode(&self) -> TunnelMode {
        **self.mode.load()
    }

    /// Активный профиль.
    pub fn active(&self) -> OutboundId {
        (**self.active.load()).clone()
    }

    /// Сколько правил в наборе.
    pub fn rule_count(&self) -> usize {
        self.rules.load().len()
    }

    /// Текущий набор правил.
    ///
    /// Снимок: правки из интерфейса заменят набор целиком, а уже взятая
    /// ссылка продолжит указывать на прежний — именно этого и хочет тот, кто
    /// обходит правила по порядку.
    pub fn rule_set(&self) -> arc_swap::Guard<std::sync::Arc<RuleSet>> {
        self.rules.load()
    }

    /// Кэш решений пуст. Для диагностики и тестов.
    pub fn cache_is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Решение по соединению.
    pub fn resolve(&self, flow: &FlowContext) -> Verdict {
        if let Some(cached) = self.cache.get(flow) {
            return cached.cached();
        }
        let verdict = self.evaluate(flow);
        self.cache.insert(flow, &verdict);
        verdict
    }

    /// Решение без обращения к кэшу — им пользуется экран проверки.
    pub fn evaluate(&self, flow: &FlowContext) -> Verdict {
        let target = flow.as_match_target();
        let active = self.active();

        if let Some(rule) = self.rules.load().first_match(&target) {
            return Verdict::by_rule(rule.action.resolve(&active), rule.id.clone(), &rule.name);
        }

        Verdict::by_mode(default_decision(self.mode(), &active))
    }

    /// Сбрасывает кэш решений.
    pub fn invalidate(&self) {
        self.cache.clear();
    }
}

/// Решение для соединения, не подошедшего ни под одно правило.
///
/// Свободная функция: режим приходит из конфигурации, а исход — понятие
/// маршрутизатора, и добавлять метод к чужому типу нельзя.
pub fn default_decision(mode: TunnelMode, active: &OutboundId) -> ResolvedDecision {
    if mode.defaults_to_tunnel() {
        Decision::ActiveTunnel.resolve(active)
    } else {
        ResolvedDecision::Direct
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use penguin_config::schema::rule::RuleConfig;
    use penguin_core::network::Network;
    use penguin_process::identity::ProcessIdentity;
    use serde_json::json;

    use super::*;
    use crate::decision::Reason;

    fn router(mode: TunnelMode, rules: serde_json::Value) -> Router {
        let rules: Vec<RuleConfig> = serde_json::from_value(rules).expect("правила разбираются");
        let config = RoutingConfig {
            mode,
            rules,
            ..RoutingConfig::default()
        };
        Router::new(&config, OutboundId::new("home"), &CompileContext::default())
            .expect("собирается")
    }

    fn flow(destination: &str, domain: Option<&str>, process: Option<&str>) -> FlowContext {
        let destination: SocketAddr = destination.parse().expect("адрес");
        let mut flow = FlowContext::to_address(
            Network::Tcp,
            "127.0.0.1:50000".parse().expect("адрес"),
            destination,
        );
        if let Some(name) = domain {
            flow = flow.with_domain(penguin_core::address::Address::domain(name));
        }
        if let Some(path) = process {
            flow = flow.with_process(ProcessIdentity::new(1, path));
        }
        flow
    }

    #[test]
    fn full_mode_sends_everything_to_the_tunnel() {
        let router = router(TunnelMode::Full, json!([]));
        let verdict = router.resolve(&flow("1.2.3.4:443", None, None));
        assert_eq!(
            verdict.decision,
            ResolvedDecision::Tunnel(OutboundId::new("home"))
        );
        assert!(matches!(verdict.reason, Reason::Mode));
    }

    #[test]
    fn allowlist_mode_sends_everything_direct() {
        let router = router(TunnelMode::Allowlist, json!([]));
        assert_eq!(
            router.resolve(&flow("1.2.3.4:443", None, None)).decision,
            ResolvedDecision::Direct
        );
    }

    #[test]
    fn rules_beat_the_mode() {
        let router = router(
            TunnelMode::Full,
            json!([{ "id": "лан", "when": { "dest_ip": ["192.168.0.0/16"] }, "action": "direct" }]),
        );
        assert_eq!(
            router
                .resolve(&flow("192.168.1.1:443", None, None))
                .decision,
            ResolvedDecision::Direct
        );
        assert_eq!(
            router.resolve(&flow("8.8.8.8:443", None, None)).decision,
            ResolvedDecision::Tunnel(OutboundId::new("home"))
        );
    }

    #[test]
    fn allowlist_and_blocklist_coexist_in_one_set() {
        // Ровно то, ради чего условие сделано деревом: «игры мимо тоннеля, но
        // их обновления — через тоннель» записывается двумя правилами и
        // разбирается порядком, а не отдельным режимом.
        let router = router(
            TunnelMode::Full,
            json!([
                {
                    "id": "патчи-стима",
                    "priority": -10,
                    "action": { "tunnel": {} },
                    "when": { "all": [
                        { "process_name": ["steam.exe"] },
                        { "domain_suffix": ["steamcontent.com"] }
                    ]}
                },
                {
                    "id": "игры-мимо",
                    "action": "direct",
                    "when": { "process_name": ["steam.exe", "cs2.exe"] }
                }
            ]),
        );

        let patch = router.resolve(&flow(
            "1.2.3.4:443",
            Some("cdn.steamcontent.com"),
            Some("c:/steam/steam.exe"),
        ));
        assert_eq!(
            patch.decision,
            ResolvedDecision::Tunnel(OutboundId::new("home"))
        );

        let game = router.resolve(&flow("5.6.7.8:27015", None, Some("c:/steam/steam.exe")));
        assert_eq!(game.decision, ResolvedDecision::Direct);
    }

    #[test]
    fn verdict_names_the_rule() {
        let router = router(
            TunnelMode::Full,
            json!([{ "id": "r1", "name": "Локальная сеть", "when": { "dest_ip": ["10.0.0.0/8"] }, "action": "direct" }]),
        );
        let verdict = router.resolve(&flow("10.1.2.3:443", None, None));
        assert_eq!(verdict.reason.to_string(), "правило «Локальная сеть»");
    }

    #[test]
    fn second_lookup_comes_from_the_cache() {
        let router = router(TunnelMode::Full, json!([]));
        let first = router.resolve(&flow("1.2.3.4:443", None, None));
        let second = router.resolve(&flow("1.2.3.4:443", None, None));
        assert!(matches!(first.reason, Reason::Mode));
        assert!(matches!(second.reason, Reason::Cached(_)));
        assert_eq!(first.decision, second.decision);
    }

    #[test]
    fn changing_rules_clears_the_cache() {
        let router = router(TunnelMode::Full, json!([]));
        router.resolve(&flow("1.2.3.4:443", None, None));

        let rules: Vec<RuleConfig> = serde_json::from_value(json!([
            { "id": "всё-напрямую", "when": { "dest_ip": ["0.0.0.0/0"] }, "action": "direct" }
        ]))
        .expect("правила разбираются");
        let config = RoutingConfig {
            mode: TunnelMode::Full,
            rules,
            ..RoutingConfig::default()
        };
        router
            .replace_rules(&config, &CompileContext::default())
            .expect("правила заменены");

        // Кэш обязан обнулиться, иначе новое правило не подействует на уже
        // виденные адреса.
        let verdict = router.resolve(&flow("1.2.3.4:443", None, None));
        assert_eq!(verdict.decision, ResolvedDecision::Direct);
    }

    #[test]
    fn switching_profile_redirects_active_tunnel_rules() {
        let router = router(TunnelMode::Full, json!([]));
        assert_eq!(
            router.resolve(&flow("1.2.3.4:443", None, None)).decision,
            ResolvedDecision::Tunnel(OutboundId::new("home"))
        );

        router.set_active(OutboundId::new("office"));
        assert_eq!(
            router.resolve(&flow("1.2.3.4:443", None, None)).decision,
            ResolvedDecision::Tunnel(OutboundId::new("office"))
        );
    }

    #[test]
    fn unknown_process_falls_back_to_the_mode() {
        // Владелец мог не определиться из-за гонки. Такое соединение уходит
        // по умолчанию, а не блокируется: «не знаю чьё» и «ничьё» — разное.
        let router = router(
            TunnelMode::Full,
            json!([{ "id": "r1", "when": { "process_name": ["app.exe"] }, "action": "direct" }]),
        );
        let verdict = router.resolve(&flow("1.2.3.4:443", None, None));
        assert_eq!(
            verdict.decision,
            ResolvedDecision::Tunnel(OutboundId::new("home"))
        );
    }

    #[test]
    fn block_rules_work() {
        let router = router(
            TunnelMode::Full,
            json!([{ "id": "реклама", "when": { "domain_keyword": ["doubleclick"] }, "action": "block" }]),
        );
        let verdict = router.resolve(&flow("1.2.3.4:443", Some("ad.doubleclick.net"), None));
        assert_eq!(verdict.decision, ResolvedDecision::Block);
    }
}
