//! `Engine` — запуск, остановка, смена профиля на лету.
//!
//! Единственный владелец тоннеля: настройки, маршрутизатор, направления,
//! платформа. `disconnect` откатывает всё в обратном порядке.

use std::sync::Arc;

use arc_swap::ArcSwap;
use penguin_config::RootConfig;
use penguin_config::schema::profile::Profile;
use penguin_core::id::{OutboundId, ProfileId};
use penguin_core::state::TunnelState;
use penguin_process::resolver::FlowOwnerResolver;
use penguin_proto::dialer::Dialer;
use penguin_router::engine::Router;
use penguin_router::ruleset::CompileContext;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::direct::SystemDialer;
use crate::error::{EngineError, EngineResult};
use crate::events::{Event, EventBus, LogLevel};
use crate::metrics::counters::Metrics;
use crate::metrics::history::History;
use crate::outbounds::OutboundPool;
use crate::pipeline::Pipeline;
use crate::pipeline::live::LiveFlows;
use crate::state::StateMachine;
use crate::tunnel::TunnelSession;

/// Шаг между замерами скорости (шаг графика в окне).
const METRICS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Движок клиента.
pub struct Engine {
    config: ArcSwap<RootConfig>,
    router: Arc<Router>,
    outbounds: Arc<OutboundPool>,
    /// Набиратель из пула: его сокеты защищаются физическим интерфейсом
    /// ([`SystemDialer::protect_with`]).
    dialer: Arc<SystemDialer>,
    processes: Arc<dyn FlowOwnerResolver>,
    metrics: Arc<Metrics>,
    /// Живые соединения всех конвейеров: их пересматривает смена правил.
    flows: Arc<LiveFlows>,
    state: Arc<StateMachine>,
    events: EventBus,
    /// Поднятый тоннель; `Mutex` разводит подключение и отключение.
    session: Mutex<Option<TunnelSession>>,
    /// Отмена идущего подключения: рукопожатие держит `session` до конца,
    /// и отключение без этого ждало бы его.
    connecting: parking_lot::Mutex<Option<CancellationToken>>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("state", &self.state.current())
            .field("router", &self.router)
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Собирает движок по настройкам.
    pub fn new(config: RootConfig) -> EngineResult<Arc<Self>> {
        let events = EventBus::new();

        let dialer = Arc::new(SystemDialer::bootstrapped(&config.dns));
        let outbounds = Arc::new(OutboundPool::new(Arc::clone(&dialer) as Arc<dyn Dialer>));

        let active = config
            .active()
            .map(|p| OutboundId::from(p.id.clone()))
            .unwrap_or_else(OutboundId::direct);

        let router = Arc::new(
            Router::new(&config.routing, active, &CompileContext::default())
                .map_err(EngineError::Router)?,
        );

        let processes: Arc<dyn FlowOwnerResolver> = if config.routing.resolve_process {
            Arc::from(penguin_process::resolver::system_resolver())
        } else {
            Arc::new(penguin_process::resolver::NoResolver)
        };

        Ok(Arc::new(Self {
            config: ArcSwap::from_pointee(config),
            router,
            outbounds,
            dialer,
            processes,
            metrics: Metrics::new(),
            flows: LiveFlows::new(),
            state: Arc::new(StateMachine::new(events.clone())),
            events,
            session: Mutex::new(None),
            connecting: parking_lot::Mutex::new(None),
        }))
    }

    /// Текущее состояние тоннеля.
    pub fn state(&self) -> TunnelState {
        self.state.current()
    }

    /// Шина событий.
    pub fn events(&self) -> &EventBus {
        &self.events
    }

    /// Учёт трафика.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Маршрутизатор.
    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    /// Пул направлений.
    pub fn outbounds(&self) -> &Arc<OutboundPool> {
        &self.outbounds
    }

    /// Текущие настройки.
    pub fn config(&self) -> Arc<RootConfig> {
        self.config.load_full()
    }

    /// Собирает конвейер обработки соединений.
    pub fn pipeline(&self) -> Arc<Pipeline> {
        let config = self.config();
        Arc::new(
            Pipeline::new(
                Arc::clone(&self.router),
                Arc::clone(&self.outbounds),
                Arc::clone(&self.processes),
                Arc::clone(&self.metrics),
            )
            .with_process_lookup(config.routing.resolve_process)
            .with_events(self.events.clone())
            .with_flows(Arc::clone(&self.flows)),
        )
    }

    /// Поднимает тоннель; при уже поднятом — не ошибка.
    pub async fn connect(&self, profile: Option<ProfileId>) -> EngineResult<()> {
        let mut session = self.session.lock().await;
        if session.is_some() {
            tracing::debug!("тоннель уже поднят");
            return Ok(());
        }

        let config = self.config();
        let profile = self.pick_profile(&config, profile.as_ref())?;
        let profile_id = profile.id.clone();

        // До «подключаемся»: увидевший это состояние должен успеть отменить.
        let abort = CancellationToken::new();
        *self.connecting.lock() = Some(abort.clone());
        self.state.connecting(profile_id.clone());
        self.events.emit(Event::log(
            LogLevel::Info,
            format!("подключение к профилю «{}»", profile.name),
        ));

        // Без защиты переподключение при поднятом тоннеле уйдёт в сам тоннель.
        match penguin_platform::default_route() {
            Ok(outside) => self.dialer.protect_with(outside.interface_index),
            Err(err) => {
                tracing::warn!(%err, "путь наружу неизвестен — сокет до сервера не защищён")
            }
        }

        let connected = tokio::select! {
            result = self.outbounds.get_or_connect(profile) => Some(result),
            () = abort.cancelled() => None,
        };
        self.connecting.lock().take();

        let outbound = match connected {
            Some(Ok(outbound)) => outbound,
            None => {
                self.dialer.protect_with(0);
                self.state.disconnected();
                self.events
                    .emit(Event::log(LogLevel::Info, "подключение отменено"));
                return Ok(());
            }
            Some(Err(err)) => {
                self.state.failed(err.to_string());
                return Err(EngineError::Protocol(err));
            }
        };

        self.router.set_active(outbound.id());
        self.metrics.reset();

        let cancel = CancellationToken::new();
        let started =
            TunnelSession::start(&config, self.pipeline(), outbound.id(), cancel.clone()).await;

        match started {
            Ok(started) => {
                *session = Some(started);
                self.state.connected(profile_id);
                self.spawn_metrics_ticker(cancel);
                self.events
                    .emit(Event::log(LogLevel::Info, "тоннель поднят"));
                Ok(())
            }
            Err(err) => {
                self.outbounds.close(&outbound.id()).await;
                self.dialer.protect_with(0);
                self.state.failed(err.to_string());
                Err(err)
            }
        }
    }

    /// Рассылает замеры скорости событиями до отмены сеанса.
    fn spawn_metrics_ticker(&self, cancel: CancellationToken) {
        let metrics = Arc::clone(&self.metrics);
        let events = self.events.clone();

        tokio::spawn(async move {
            let mut history = History::new();
            let mut ticker = tokio::time::interval(METRICS_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Первый тик мгновенный: съедаем, чтобы не делить на нулевое время.
            ticker.tick().await;

            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    _ = ticker.tick() => {}
                }

                let total = metrics.total();
                let rate = history.push(total, METRICS_INTERVAL.as_secs_f64());

                events.emit(Event::Throughput {
                    rate,
                    total,
                    connections: metrics.live_connections(),
                });
            }
        });
    }

    /// Опускает тоннель; возвращает первую ошибку, откат идёт до конца.
    pub async fn disconnect(&self) -> EngineResult<()> {
        // До замка: его держит подключение, пока ждёт сервер.
        if let Some(abort) = self.connecting.lock().take() {
            abort.cancel();
        }
        let mut session = self.session.lock().await;
        // Снимается всегда: интерфейса после смены сети может не быть.
        self.dialer.protect_with(0);

        let Some(started) = session.take() else {
            self.state.disconnected();
            return Ok(());
        };

        self.state.set(TunnelState::Disconnecting);
        let result = started.stop().await;
        self.outbounds.close_all().await;

        self.state.disconnected();
        self.events
            .emit(Event::log(LogLevel::Info, "тоннель опущен"));
        result
    }

    /// Заменяет настройки на лету, не перезапуская тоннель; соединения, которые новые
    /// правила ведут иначе, обрываются — приложения тут же откроют их заново.
    pub fn reload(&self, config: RootConfig) -> EngineResult<()> {
        self.router
            .replace_rules(&config.routing, &CompileContext::default())
            .map_err(EngineError::Router)?;

        let revoked = self
            .flows
            .revise(|flow| self.router.evaluate(flow).decision);
        if revoked > 0 {
            self.events.emit(Event::log(
                LogLevel::Info,
                format!("соединений под изменёнными правилами пересоздаётся: {revoked}"),
            ));
        }

        let count = self.router.rule_count();
        self.config.store(Arc::new(config));
        self.events.emit(Event::RulesReloaded { count });
        tracing::info!(count, "правила пересобраны");
        Ok(())
    }

    /// Выбирает профиль.
    fn pick_profile<'a>(
        &self,
        config: &'a RootConfig,
        wanted: Option<&ProfileId>,
    ) -> EngineResult<&'a Profile> {
        match wanted {
            Some(id) => config
                .profile(id)
                .ok_or_else(|| EngineError::NoSuchProfile(id.to_string())),
            None => config.active().ok_or(EngineError::NoProfiles),
        }
    }
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::outbound::RawOutbound;
    use serde_json::json;

    use super::*;

    fn config_with_profiles(ids: &[&str]) -> RootConfig {
        let mut config = RootConfig::default();
        for id in ids {
            config.profiles.push(Profile::new(
                *id,
                *id,
                RawOutbound::new(
                    "hysteria2",
                    json!({ "server": "example.com:443", "auth": "x" }),
                ),
            ));
        }
        config
    }

    #[test]
    fn starts_disconnected() {
        let engine = Engine::new(config_with_profiles(&["home"])).expect("собирается");
        assert_eq!(engine.state(), TunnelState::Disconnected);
    }

    #[test]
    fn picks_the_active_profile_by_default() {
        let engine = Engine::new(config_with_profiles(&["home", "office"])).expect("собирается");
        let config = engine.config();
        let profile = engine.pick_profile(&config, None).expect("профиль есть");
        assert_eq!(profile.id.as_str(), "home");
    }

    #[test]
    fn unknown_profile_is_named_in_the_error() {
        let engine = Engine::new(config_with_profiles(&["home"])).expect("собирается");
        let config = engine.config();
        let err = engine
            .pick_profile(&config, Some(&ProfileId::new("нет-такого")))
            .expect_err("профиля нет");
        assert!(err.to_string().contains("нет-такого"));
    }

    #[test]
    fn empty_config_says_there_are_no_profiles() {
        let engine = Engine::new(RootConfig::default()).expect("собирается");
        let config = engine.config();
        assert!(matches!(
            engine.pick_profile(&config, None),
            Err(EngineError::NoProfiles)
        ));
    }

    #[tokio::test]
    async fn disconnect_without_connect_is_not_an_error() {
        let engine = Engine::new(config_with_profiles(&["home"])).expect("собирается");
        engine.disconnect().await.expect("отключение проходит");
        assert_eq!(engine.state(), TunnelState::Disconnected);
    }

    #[cfg(feature = "wireguard")]
    #[tokio::test]
    async fn disconnect_cancels_a_connect_waiting_for_the_server() {
        // Сервер, который молчит: рукопожатие ждало бы свой срок. Не на
        // петле: сокет, привязанный к физическому интерфейсу, до неё не достаёт.
        let host = penguin_platform::default_route()
            .map_or(std::net::IpAddr::from([127, 0, 0, 1]), |route| {
                route.address
            });
        let silent = tokio::net::UdpSocket::bind((host, 0)).await.expect("сокет");
        let key = penguin_core::base64::encode(&[7u8; 32]);
        let mut config = RootConfig::default();
        config.profiles.push(Profile::new(
            "wg",
            "wg",
            penguin_config::schema::outbound::RawOutbound::new(
                "wireguard",
                serde_json::json!({
                    "server": silent.local_addr().expect("адрес").to_string(),
                    "private_key": key,
                    "server_public_key": key,
                    "address_ipv4": "10.0.0.2/32",
                }),
            ),
        ));
        let engine = Engine::new(config).expect("собирается");

        let connecting = tokio::spawn({
            let engine = Arc::clone(&engine);
            async move { engine.connect(None).await }
        });
        while !matches!(engine.state(), TunnelState::Connecting { .. }) {
            tokio::task::yield_now().await;
        }

        tokio::time::timeout(std::time::Duration::from_secs(2), engine.disconnect())
            .await
            .expect("отключение не ждёт рукопожатия")
            .expect("отключение проходит");
        connecting
            .await
            .expect("задача")
            .expect("отменённое подключение — не ошибка");
        assert_eq!(engine.state(), TunnelState::Disconnected);
    }

    #[tokio::test]
    async fn reload_rebuilds_the_rules() {
        let engine = Engine::new(config_with_profiles(&["home"])).expect("собирается");
        assert_eq!(engine.router().rule_count(), 0);

        let mut config = config_with_profiles(&["home"]);
        config.routing.rules = serde_json::from_value(json!([
            { "id": "лан", "when": { "dest_ip": ["10.0.0.0/8"] }, "action": "direct" }
        ]))
        .expect("правила разбираются");

        engine.reload(config).expect("правила применяются");
        assert_eq!(engine.router().rule_count(), 1);
    }

    #[tokio::test]
    async fn reload_drops_only_the_connections_the_new_rules_route_elsewhere() {
        use penguin_core::network::Network;
        use penguin_router::context::FlowContext;

        let engine = Engine::new(config_with_profiles(&["home"])).expect("собирается");
        let open = |target: &str| {
            let flow = FlowContext::to_target(
                Network::Tcp,
                "198.18.0.7:50000".parse().expect("адрес"),
                target.parse().expect("адрес"),
            );
            let decision = engine.router().evaluate(&flow).decision;
            engine.flows.register(flow, decision)
        };
        let lan = open("10.1.2.3:443");
        let internet = open("1.1.1.1:443");

        let mut config = config_with_profiles(&["home"]);
        config.routing.rules = serde_json::from_value(json!([
            { "id": "лан", "when": { "dest_ip": ["10.0.0.0/8"] }, "action": "block" }
        ]))
        .expect("правила разбираются");
        engine.reload(config).expect("правила применяются");

        assert!(lan.revoked().is_cancelled(), "правило его касается");
        assert!(
            !internet.revoked().is_cancelled(),
            "правило его не касается"
        );
    }

    #[tokio::test]
    async fn reload_with_broken_rules_keeps_the_old_ones() {
        let engine = Engine::new(config_with_profiles(&["home"])).expect("собирается");

        let mut good = config_with_profiles(&["home"]);
        good.routing.rules = serde_json::from_value(json!([
            { "id": "лан", "when": { "dest_ip": ["10.0.0.0/8"] }, "action": "direct" }
        ]))
        .expect("правила разбираются");
        engine.reload(good).expect("правила применяются");

        let mut broken = config_with_profiles(&["home"]);
        broken.routing.rules = serde_json::from_value(json!([
            { "id": "плохое", "when": { "dest_ip": ["не адрес"] }, "action": "direct" }
        ]))
        .expect("правила разбираются");

        assert!(engine.reload(broken).is_err());
        assert_eq!(engine.router().rule_count(), 1, "старые правила потерялись");
    }

    #[tokio::test]
    async fn state_changes_reach_subscribers() {
        let engine = Engine::new(config_with_profiles(&["home"])).expect("собирается");
        let mut events = engine.events().subscribe();

        engine.disconnect().await.expect("отключение проходит");
        assert!(matches!(
            events.recv().await.expect("событие"),
            Event::State { .. }
        ));
    }
}
