//! Поднятый тоннель: адаптер, стек, маршруты, kill switch.
//!
//! Откат идёт в обратном порядке и до конца даже после ошибки:
//!
//! ```text
//!   запуск:   kill switch ─► адаптер ─► маршруты ─► DNS ─► стек ─► сброс старых соединений
//!   останов:  стек ─► DNS ─► маршруты ─► адаптер ─► kill switch
//! ```

use std::net::IpAddr;
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
    /// Локальные прокси и насосы стека.
    inbounds: Vec<tokio::task::JoinHandle<()>>,
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

        // Прокси не требуют прав и не зависят от адаптера.
        session.start_inbounds(config, pipeline).await?;

        // Готовим до того, как система тронута: падать после неё незачем.
        if config.dns.hijack {
            session.dns = Some(Arc::new(DnsHijacker::new(&config.dns)?));
        }

        // Без прав клиент остаётся рабочим прокси.
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

        // До любых изменений: позже kill switch и сам тоннель исказят ответ.
        let servers = server_addresses(config, outbound).await;
        let outside = penguin_platform::default_route().ok();

        if servers.is_empty() {
            tracing::warn!("адрес сервера не найден — тоннель может заглушить сам себя");
        }

        // Подсеть адаптера известна заранее, поэтому запрет включается до него.
        if config.network.kill_switch {
            let rules = FirewallRules {
                tunnel_subnet: Some(tun_config.subnet()),
                allow_lan: config.network.allow_lan,
                allow_addresses: servers.clone(),
            };
            self.kill_switch.engage(&rules)?;
        }

        let device = penguin_tun::open(&tun_config).await?;
        let index = device.index().unwrap_or_default();
        tracing::info!(name = device.name(), index, "адаптер поднят");

        // Сервер выводится мимо тоннеля до маршрутов по умолчанию.
        match &outside {
            Some(outside) => {
                if let Some(foreign) = penguin_platform::interface::foreign_tunnel(outside) {
                    tracing::warn!(
                        interface = %foreign,
                        "путь наружу ведёт в чужой тоннель: соединение с сервером пойдёт \
                         через него, и если он режет QUIC (UDP 443), рукопожатие не \
                         завершится — выключите другой VPN-клиент"
                    );
                }
                self.routes.pin_outside(&servers, outside)?;
                self.routes.keep_outside_default(outside)?;
            }
            None => tracing::warn!("путь наружу неизвестен — трафик до сервера уйдёт в тоннель"),
        }

        // Две половины вместо `0.0.0.0/0`: префикс длиннее.
        if config.network.capture_default_route {
            self.routes.capture_all(index)?;
        } else {
            tracing::info!(
                "маршрут по умолчанию остаётся у системы — в тоннель пойдёт только то, \
                 что пришло в локальный прокси"
            );
        }

        // Часть служб обходит таблицу маршрутов — нужен единственный DNS.
        if config.dns.hijack {
            self.dns_settings
                .apply(index, IpAddr::V4(tun_config.ipv4.0))?;
        }

        let stack_config = penguin_netstack::StackConfig::from_tun(&tun_config);
        let handles = penguin_netstack::spawn(device, stack_config, self.cancel.clone());
        self.spawn_stack_pumps(handles, config);

        // После стека: сброшенные приложения переподключаются уже в него.
        if config.network.capture_default_route {
            tokio::spawn(crate::takeover::take_over(servers));
        }

        Ok(())
    }

    /// Запускает перекладывание между стеком и конвейером (TCP и UDP отдельно).
    fn spawn_stack_pumps(&mut self, handles: penguin_netstack::StackHandles, config: &RootConfig) {
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

    /// Опускает всё в обратном порядке, не останавливаясь на ошибках.
    pub async fn stop(mut self) -> EngineResult<()> {
        self.cancel.cancel();
        for task in self.inbounds.drain(..) {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
        }

        let mut first_error: Option<EngineError> = None;
        let mut note = |result: PlatformResult<()>, what: &str| match result {
            Ok(()) => tracing::debug!(what, "откат выполнен"),
            Err(err) => {
                tracing::error!(%err, what, "откат не завершился");
                if first_error.is_none() {
                    first_error = Some(EngineError::Platform(err));
                }
            }
        };

        note(self.dns_settings.restore(), "настройки DNS");
        note(self.routes.restore(), "маршруты");
        // Последним: до этого наружу ничего не уходит.
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

/// Запрос для проверки конвейера.
pub fn request_from(
    source: std::net::SocketAddr,
    target: penguin_core::address::SocketAddress,
    network: Network,
) -> InboundRequest {
    InboundRequest {
        source,
        target,
        sniffed: None,
        network,
    }
}

/// Адреса сервера, которые kill switch обязан пропускать: тоннель ходит к ним
/// напрямую, мимо адаптера.
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

    // Загрузочный разрешатель: системный вернул бы подставной fake-IP
    // (см. [`penguin_dns::bootstrap`]).
    penguin_proto::dialer::Dialer::resolve(
        &crate::direct::SystemDialer::bootstrapped(&config.dns),
        host_of(server),
    )
    .await
    .unwrap_or_default()
}

/// Имя сервера без порта; IPv6 полон двоеточий, поэтому отдельная функция.
fn host_of(server: &str) -> &str {
    let server = server.trim();
    if let Some(rest) = server.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }
    if server.parse::<IpAddr>().is_ok() {
        return server;
    }
    server.rsplit_once(':').map_or(server, |(host, _)| host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_port_is_dropped_and_a_bare_host_left_alone() {
        assert_eq!(host_of("example.net"), "example.net");
        assert_eq!(host_of(" example.net:3478 "), "example.net");
        assert_eq!(host_of("203.0.113.5"), "203.0.113.5");
        assert_eq!(host_of("203.0.113.5:3478"), "203.0.113.5");
    }

    #[test]
    fn an_ipv6_address_is_not_mistaken_for_a_port() {
        assert_eq!(host_of("2001:db8::1"), "2001:db8::1");
        assert_eq!(host_of("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(host_of("[2001:db8::1]:3478"), "2001:db8::1");
    }

    #[tokio::test]
    async fn a_profile_without_a_server_yields_nothing() {
        let config = RootConfig::default();
        let addresses = server_addresses(&config, &OutboundId::direct()).await;
        assert!(addresses.is_empty());
    }

    #[test]
    fn request_keeps_the_fields_apart() {
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
