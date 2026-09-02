//! Поднятый тоннель: адаптер, стек, маршруты, kill switch.
//!
//! Всё, что тоннель делает с системой, он обязан уметь отменить — и отменить
//! **в обратном порядке**. Порядок здесь не педантизм: снять маршруты до
//! того, как остановлен стек, значит на несколько миллисекунд выпустить
//! трафик мимо тоннеля; снять kill switch последним — значит гарантировать,
//! что в этот промежуток наружу не уйдёт ничего.
//!
//! ```text
//!   запуск:   kill switch ─► адаптер ─► маршруты ─► DNS ─► стек
//!   останов:  стек ─► DNS ─► маршруты ─► адаптер ─► kill switch
//! ```
//!
//! Отмена идёт до конца даже после ошибки. Недоснятый маршрут — не повод
//! оставить в системе ещё и правила брандмауэра: пользователь получит машину
//! без сети и не свяжет это с закрытым клиентом.

use std::sync::Arc;

use penguin_config::RootConfig;
use penguin_core::id::OutboundId;
use penguin_core::network::Network;
use penguin_dns::hijack::DnsHijacker;
use penguin_inbound::inbound::{Inbound, InboundHandler, InboundRequest};
use penguin_platform::firewall::{FirewallRules, KillSwitch};
use penguin_platform::route::RouteGuard;
use penguin_platform::{DnsOverrideHandle, PlatformResult};
use penguin_tun::TunConfig;
use std::net::IpAddr;
use tokio_util::sync::CancellationToken;

use crate::error::{EngineError, EngineResult};
use crate::pipeline::Pipeline;

/// Поднятый тоннель.
pub struct TunnelSession {
    cancel: CancellationToken,
    pipeline: Arc<Pipeline>,
    routes: RouteGuard,
    kill_switch: KillSwitch,
    dns_settings: DnsOverrideHandle,
    /// Локальные прокси, поднятые вместе с тоннелем.
    inbounds: Vec<tokio::task::JoinHandle<()>>,
    /// Перехват DNS, если он включён.
    dns: Option<Arc<DnsHijacker>>,
}

impl std::fmt::Debug for TunnelSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelSession")
            .field("routes", &self.routes.len())
            .field("kill_switch", &self.kill_switch.is_engaged())
            .field("inbounds", &self.inbounds.len())
            .finish()
    }
}

impl TunnelSession {
    /// Поднимает всё, что нужно тоннелю.
    pub async fn start(
        config: &RootConfig,
        pipeline: Arc<Pipeline>,
        outbound: OutboundId,
        cancel: CancellationToken,
    ) -> EngineResult<Self> {
        let mut session = Self {
            cancel: cancel.clone(),
            pipeline: Arc::clone(&pipeline),
            routes: RouteGuard::new(),
            kill_switch: KillSwitch::new(),
            dns_settings: DnsOverrideHandle::new(),
            inbounds: Vec::new(),
            dns: None,
        };

        // Локальные прокси поднимаются всегда, когда заданы: они не требуют
        // прав и работают независимо от того, поднялся ли адаптер.
        session.start_inbounds(config, pipeline).await?;

        // Перехват DNS готовится до адаптера: собрать его — чистая работа с
        // настройками, и падать на ней после того, как система уже тронута,
        // незачем.
        if config.dns.hijack {
            session.dns = Some(Arc::new(DnsHijacker::new(&config.dns)?));
        }

        // Адаптер и всё остальное — только там, где есть права. Без них
        // клиент остаётся рабочим прокси, а не превращается в неработающий
        // тоннель.
        if penguin_platform::is_elevated() {
            session.start_tunnel(config, &outbound).await?;
        } else {
            tracing::warn!(
                "нет прав администратора — тоннель не поднимается, работает только прокси"
            );
        }

        Ok(session)
    }

    /// Поднимает локальные прокси.
    async fn start_inbounds(
        &mut self,
        config: &RootConfig,
        pipeline: Arc<Pipeline>,
    ) -> EngineResult<()> {
        if let Some(socks) = &config.network.socks {
            let credentials = socks
                .auth
                .as_ref()
                .map(|auth| penguin_inbound::Credentials {
                    username: auth.username.clone(),
                    password: auth.password.clone(),
                });
            let inbound = penguin_inbound::Socks5Inbound::bind(
                socks.listen,
                Arc::clone(&pipeline) as Arc<dyn InboundHandler>,
                credentials,
            )
            .await?;
            self.spawn_inbound(Box::new(inbound));
        }

        if let Some(http) = &config.network.http {
            let inbound = penguin_inbound::HttpInbound::bind(
                http.listen,
                Arc::clone(&pipeline) as Arc<dyn InboundHandler>,
            )
            .await?;
            self.spawn_inbound(Box::new(inbound));
        }

        Ok(())
    }

    fn spawn_inbound(&mut self, inbound: Box<dyn Inbound>) {
        let cancel = self.cancel.clone();
        self.inbounds
            .push(tokio::spawn(async move { inbound.serve(cancel).await }));
    }

    /// Поднимает адаптер, маршруты и стек.
    async fn start_tunnel(
        &mut self,
        config: &RootConfig,
        outbound: &OutboundId,
    ) -> EngineResult<()> {
        let tun_config = TunConfig::from_schema(&config.network.tun);

        // Адреса сервера и путь наружу спрашиваются до того, как что-либо
        // тронуто. Позже будет поздно: своё же разрешение имён перекроет kill
        // switch, а на вопрос «как машина выходит наружу» ответом станет сам
        // тоннель.
        let servers = server_addresses(config, outbound).await;
        let outside = penguin_platform::default_route().ok();

        if servers.is_empty() {
            tracing::warn!("адрес сервера не найден — тоннель может заглушить сам себя");
        }

        // Kill switch включается **до** адаптера: пока тоннеля нет, наружу не
        // должно уйти ничего, даже в те доли секунды, что занимает запуск.
        if config.network.kill_switch {
            let rules = FirewallRules {
                // Подсеть адаптера известна из настроек — до того, как он
                // создан. Это и позволяет включить запрет заранее, не оставив
                // мига, когда наружу уже можно, а тоннеля ещё нет.
                tunnel_subnet: Some(tun_config.subnet()),
                allow_lan: config.network.allow_lan,
                allow_addresses: servers.clone(),
            };
            self.kill_switch.engage(&rules)?;
        }

        let device = penguin_tun::open(&tun_config).await?;
        let index = device.index().unwrap_or_default();
        tracing::info!(name = device.name(), index, "адаптер поднят");

        // Сервер выводится мимо тоннеля — раньше, чем ставятся маршруты по
        // умолчанию. Иначе пакеты до него заворачиваются в собственный
        // адаптер, и клиент разговаривает сам с собой: не работает ни тоннель,
        // ни даже проверка задержки.
        match &outside {
            Some(outside) => self.routes.pin_outside(&servers, outside)?,
            None => tracing::warn!("путь наружу неизвестен — трафик до сервера уйдёт в тоннель"),
        }

        // Маршруты — двумя половинами вместо `0.0.0.0/0`: их префикс длиннее,
        // и система выбирает их раньше любого маршрута по умолчанию.
        self.routes.capture_all(index)?;

        // Свой адрес объявляется единственным DNS: перехвата порта 53 из TUN
        // хватает не всегда — часть системных служб обходит таблицу
        // маршрутизации.
        if config.dns.hijack {
            self.dns_settings
                .apply(index, std::net::IpAddr::V4(tun_config.ipv4.0))?;
        }

        let stack_config = penguin_netstack::StackConfig::from_tun(&tun_config);
        let handles = penguin_netstack::spawn(device, stack_config, self.cancel.clone());
        self.spawn_stack_pumps(handles, config);

        Ok(())
    }

    /// Запускает перекладывание между стеком и конвейером.
    ///
    /// Две задачи, потому что TCP и UDP приходят из стека по разным каналам и
    /// живут по разным правилам: у первого есть состояние и закрытие, у
    /// второго нет ни того ни другого.
    fn spawn_stack_pumps(&mut self, handles: penguin_netstack::StackHandles, config: &RootConfig) {
        // Соответствие подставных адресов и имён общее для обоих направлений:
        // приложение спрашивает имя один раз, а ходит и по TCP, и по UDP.
        let fake_ip = self.dns.as_ref().and_then(|dns| dns.fake_ip().cloned());

        self.inbounds.push(tokio::spawn(crate::pipeline::tcp::pump(
            handles.tcp,
            Arc::clone(&self.pipeline),
            fake_ip.clone(),
            config.routing.sniff,
            self.cancel.clone(),
        )));

        self.inbounds.push(tokio::spawn(crate::pipeline::udp::pump(
            handles.udp_incoming,
            handles.udp_outgoing,
            Arc::clone(&self.pipeline),
            self.dns.clone(),
            fake_ip,
            self.cancel.clone(),
        )));
    }

    /// Опускает всё в обратном порядке.
    ///
    /// Продолжает после ошибки: недоснятый маршрут — не повод оставить в
    /// системе ещё и правила брандмауэра.
    pub async fn stop(mut self) -> EngineResult<()> {
        // 1. Стек и входящие точки. Отмена доходит до всех задач разом.
        self.cancel.cancel();
        for task in self.inbounds.drain(..) {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
        }

        let mut first_error: Option<EngineError> = None;
        let mut note = |result: PlatformResult<()>, what: &str| {
            if let Err(err) = result {
                tracing::error!(%err, what, "откат не завершился");
                if first_error.is_none() {
                    first_error = Some(EngineError::Platform(err));
                }
            }
        };

        // 2. Настройки DNS. Оставленный адрес указывает на исчезнувший
        //    адаптер, и у пользователя перестают открываться сайты.
        note(self.dns_settings.restore(), "настройки DNS");

        // 3. Маршруты. Оставленный маршрут ведёт в несуществующий адаптер.
        note(self.routes.restore(), "маршруты");

        // 4. Kill switch — последним: до этого момента наружу ничего не
        //    уходит, и промежутка без защиты не возникает.
        note(self.kill_switch.disengage(), "kill switch");

        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Перехват DNS, если он включён.
    pub fn dns(&self) -> Option<&Arc<DnsHijacker>> {
        self.dns.as_ref()
    }
}

/// Заглушка запроса для проверки конвейера.
///
/// Отдельная функция, потому что собрать её правильно — вопрос порядка полей,
/// который легко перепутать местами.
pub fn request_from(
    source: std::net::SocketAddr,
    target: penguin_core::address::SocketAddress,
    network: Network,
) -> InboundRequest {
    InboundRequest {
        source,
        target,
        network,
    }
}

/// Адреса сервера, до которых kill switch обязан пропускать.
///
/// Трафик тоннеля идёт до сервера **напрямую**, мимо адаптера: он и есть тот
/// самый трафик, ради которого всё поднимается. Под общий запрет он попадает
/// первым, и тогда тоннель глушит сам себя.
async fn server_addresses(config: &RootConfig, outbound: &OutboundId) -> Vec<IpAddr> {
    let Some(profile) = config
        .profiles
        .iter()
        .find(|profile| OutboundId::from(profile.id.clone()) == *outbound)
    else {
        return Vec::new();
    };

    let Some(server) = profile
        .outbound
        .field("server")
        .and_then(serde_json::Value::as_str)
    else {
        return Vec::new();
    };

    tokio::net::lookup_host(with_port(server.trim()))
        .await
        .map(|found| found.map(|address| address.ip()).collect())
        .unwrap_or_default()
}

/// Дописывает порт, если его нет.
///
/// Разрешение имён требует порт, а в настройках сервер может стоять и без
/// него. Свободная функция с тестом: адрес IPv6 сам полон двоеточий, и
/// проверка «есть двоеточие — значит есть порт» на нём ломается.
fn with_port(server: &str) -> String {
    // Уже с портом — в том числе `[::1]:443`.
    if server.parse::<std::net::SocketAddr>().is_ok() {
        return server.to_owned();
    }
    // Голый адрес IPv6: двоеточий много, а порта нет.
    if server.parse::<IpAddr>().is_ok() {
        return format!("{server}:{DEFAULT_PORT}");
    }
    if server.contains(':') {
        return server.to_owned();
    }
    format!("{server}:{DEFAULT_PORT}")
}

/// Порт, если в настройках его не указали.
const DEFAULT_PORT: u16 = 443;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_without_a_port_gets_one() {
        assert_eq!(with_port("example.net"), "example.net:443");
        assert_eq!(with_port("203.0.113.5"), "203.0.113.5:443");
    }

    #[test]
    fn a_server_with_a_port_is_left_alone() {
        assert_eq!(with_port("example.net:3478"), "example.net:3478");
        assert_eq!(with_port("203.0.113.5:3478"), "203.0.113.5:3478");
    }

    #[test]
    fn an_ipv6_address_is_not_mistaken_for_a_port() {
        // Двоеточий в нём много, а порта нет: проверка «есть двоеточие —
        // значит есть порт» дала бы неразрешимый адрес, и kill switch
        // перекрыл бы сам тоннель.
        assert_eq!(with_port("2001:db8::1"), "2001:db8::1:443");
        assert_eq!(with_port("[2001:db8::1]:3478"), "[2001:db8::1]:3478");
    }

    #[tokio::test]
    async fn a_profile_without_a_server_yields_nothing() {
        // Пустой список означает kill switch, который заглушит тоннель;
        // молчать об этом нельзя, но и падать здесь нечем.
        let config = RootConfig::default();
        let addresses = server_addresses(&config, &OutboundId::direct()).await;
        assert!(addresses.is_empty());
    }

    #[test]
    fn request_keeps_the_fields_apart() {
        // Источник и назначение перепутать легко, а последствие — трафик,
        // уехавший не туда.
        let request = request_from(
            "127.0.0.1:50000".parse().expect("адрес"),
            "example.com:443".parse().expect("адрес"),
            Network::Tcp,
        );
        assert_eq!(request.source.port(), 50000);
        assert_eq!(request.target.port, 443);
        assert_eq!(request.network, Network::Tcp);
    }
}
