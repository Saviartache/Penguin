//! `Engine` — запуск, остановка, смена профиля на лету.
//!
//! Здесь собирается всё: настройки, маршрутизатор, направления, входящие
//! точки, платформа. Ровно один тип, который держит тоннель, и ровно один
//! способ его попросить что-то сделать.
//!
//! ```text
//!   connect(профиль)
//!     ├─ поднять направление (протокол)
//!     ├─ открыть адаптер, поставить маршруты      ─┐
//!     ├─ запустить стек и перехват DNS             ├─ только режим тоннеля
//!     └─ включить kill switch                     ─┘
//!
//!   disconnect()
//!     └─ всё то же самое в обратном порядке, включая аварийный путь
//! ```
//!
//! Порядок отката важнее порядка запуска. Маршрут, оставшийся от упавшего
//! клиента, ведёт в несуществующий адаптер, и сеть у пользователя не работает
//! вовсе — причём он не свяжет это с VPN, который уже закрыл.

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
use crate::state::StateMachine;
use crate::tunnel::TunnelSession;

/// Шаг между замерами скорости.
///
/// Секунда — шаг графика в окне. Реже — рваная линия, чаще — обмен по каналу
/// ради цифр, которые глазом всё равно не различить.
const METRICS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Движок клиента.
pub struct Engine {
    config: ArcSwap<RootConfig>,
    router: Arc<Router>,
    outbounds: Arc<OutboundPool>,
    /// Набиратель прямого выхода — тот самый, что лежит в пуле направлений.
    ///
    /// Держится отдельно ради одного: пока тоннель поднят, его сокеты надо
    /// защищать физическим интерфейсом, а пул отдаёт направления, а не
    /// набирателя (см. [`SystemDialer::protect_with`]).
    dialer: Arc<SystemDialer>,
    processes: Arc<dyn FlowOwnerResolver>,
    metrics: Arc<Metrics>,
    state: Arc<StateMachine>,
    events: EventBus,
    /// Поднятый тоннель, если он есть.
    ///
    /// Под `Mutex`, потому что подключение и отключение не должны идти
    /// одновременно: два нажатия «подключить» подряд — обычное дело.
    session: Mutex<Option<TunnelSession>>,
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

        // Загрузочный, а не системный. Имя своего сервера клиент обязан
        // спрашивать мимо системы: системный резолвер он сам же и подменяет —
        // и на вопрос об имени сервера отвечает подставным адресом из подсети
        // тоннеля, которого ещё нет. Клиент звонит сам себе, и это выглядит как
        // «рукопожатие не завершилось» (см. [`penguin_dns::bootstrap`]).
        //
        // Системный остаётся запасным: без загрузочных апстримов в настройках
        // разрешать имена лучше плохо, чем никак.
        let resolver = penguin_dns::bootstrap::resolver_for(&config.dns);
        let dialer = Arc::new(SystemDialer::new(resolver));
        let outbounds = Arc::new(OutboundPool::new(Arc::clone(&dialer) as Arc<dyn Dialer>));

        let active = config
            .active()
            .map(|p| OutboundId::from(p.id.clone()))
            .unwrap_or_else(OutboundId::direct);

        let router = Arc::new(
            Router::new(&config.routing, active, &CompileContext::default())
                .map_err(EngineError::Router)?,
        );

        // Владелец соединения ищется, только если правила по процессам вообще
        // есть: чтение таблицы соединений стоит системного вызова на каждое
        // новое соединение.
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
            state: Arc::new(StateMachine::new(events.clone())),
            events,
            session: Mutex::new(None),
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
            // Решения по соединениям уезжают в окно: без них журнал знает
            // только про подъём и падение тоннеля.
            .with_events(self.events.clone()),
        )
    }

    /// Поднимает тоннель.
    ///
    /// Повторный вызов при уже поднятом тоннеле — не ошибка: пользователь мог
    /// нажать «подключить» дважды.
    pub async fn connect(&self, profile: Option<ProfileId>) -> EngineResult<()> {
        let mut session = self.session.lock().await;
        if session.is_some() {
            tracing::debug!("тоннель уже поднят");
            return Ok(());
        }

        let config = self.config();
        let profile = self.pick_profile(&config, profile.as_ref())?;
        let profile_id = profile.id.clone();

        self.state.connecting(profile_id.clone());
        self.events.emit(Event::log(
            LogLevel::Info,
            format!("подключение к профилю «{}»", profile.name),
        ));

        // Путь наружу запоминается до набора и остаётся у набирателя на всё
        // время тоннеля. Первое рукопожатие уходит и без этого — тоннеля ещё
        // нет, — но соединение с сервером живёт дольше рукопожатия, а
        // переподключение случается уже при поднятом тоннеле. Без защиты такой
        // сокет уезжает в собственный тоннель, и клиент разговаривает сам с
        // собой: «рукопожатие не завершилось».
        match penguin_platform::default_route() {
            Ok(outside) => self.dialer.protect_with(outside.interface_index),
            Err(err) => {
                tracing::warn!(%err, "путь наружу неизвестен — сокет до сервера не защищён")
            }
        }

        // Направление поднимается первым: без него остальное бессмысленно, а
        // откатывать ещё нечего.
        let outbound = match self.outbounds.get_or_connect(profile).await {
            Ok(outbound) => outbound,
            Err(err) => {
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
                // Направление уже поднято — закрываем, иначе останется висеть
                // соединение к серверу без всякого тоннеля.
                self.outbounds.close(&outbound.id()).await;
                self.dialer.protect_with(0);
                self.state.failed(err.to_string());
                Err(err)
            }
        }
    }

    /// Запускает рассылку замеров скорости.
    ///
    /// Интерфейс не опрашивает демона, а слушает его — и перерисовывается
    /// только на событиях. Без этих замеров график скорости стоит на нуле, а
    /// счётчик времени работы показывает `0:00` до самого отключения: тоннель
    /// работает, а по окну этого не видно.
    ///
    /// Задача живёт ровно столько же, сколько сеанс: отмена приходит тем же
    /// признаком, что и всему остальному в тоннеле.
    fn spawn_metrics_ticker(&self, cancel: CancellationToken) {
        let metrics = Arc::clone(&self.metrics);
        let events = self.events.clone();

        tokio::spawn(async move {
            let mut history = History::new();
            let mut ticker = tokio::time::interval(METRICS_INTERVAL);
            // Пропущенные тики не навёрстываются пачкой: скорость за уже
            // прошедшее время никому не интересна.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Первый тик срабатывает немедленно; его надо съесть, иначе первая
            // скорость посчиталась бы делением на нулевое время.
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

    /// Опускает тоннель.
    ///
    /// Возвращает первую ошибку, но продолжает откат до конца: недоснятый
    /// маршрут не повод оставить в системе ещё и правила брандмауэра.
    pub async fn disconnect(&self) -> EngineResult<()> {
        let mut session = self.session.lock().await;
        // Защита снимается в любом случае, даже когда тоннеля не было: она
        // держит сокеты на интерфейсе, которого после смены сети может уже не
        // быть, и оставленная лишний раз она вреднее, чем не поставленная.
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

    /// Заменяет настройки на лету.
    ///
    /// Правила и режим применяются сразу; тоннель при этом не перезапускается.
    pub fn reload(&self, config: RootConfig) -> EngineResult<()> {
        self.router
            .replace_rules(&config.routing, &CompileContext::default())
            .map_err(EngineError::Router)?;

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
        // Пользователь нажимает «отключить» на уже отключённом клиенте —
        // обычное дело.
        let engine = Engine::new(config_with_profiles(&["home"])).expect("собирается");
        engine.disconnect().await.expect("отключение проходит");
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
    async fn reload_with_broken_rules_keeps_the_old_ones() {
        // Половина применённых правил хуже, чем неприменённые: трафик пошёл
        // бы не туда, а пользователь считал бы, что настройки в силе.
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
