//! Обработка одного соединения от приёма до закрытия.
//!
//! ```text
//!   входящая точка (SOCKS5 / HTTP / TUN)
//!         │  «хочу соединиться с X»
//!         ▼
//!   кто владелец? ──► penguin-process
//!         ▼
//!   куда вести? ────► penguin-router
//!         ▼
//!   ┌─ Tunnel ─► направление из пула ─► протокол
//!   ├─ Direct ─► прямой выход
//!   └─ Block ──► отказ
//!         ▼
//!   поток с учётом трафика — обратно входящей точке
//! ```

pub mod copy;
pub mod live;
pub mod revocable;
pub mod tcp;
pub mod udp;

use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::id::OutboundId;
use penguin_core::id::RuleId;
use penguin_inbound::inbound::{InboundHandler, InboundRequest};
use penguin_process::resolver::FlowOwnerResolver;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use penguin_router::context::FlowContext;
use penguin_router::decision::{Reason, ResolvedDecision, Verdict};
use penguin_router::engine::Router;

use crate::events::{Event, EventBus};

use crate::metrics::counters::Metrics;
use crate::outbounds::OutboundPool;
use crate::pipeline::copy::Metered;
use crate::pipeline::live::LiveFlows;
use crate::pipeline::revocable::{RevocableDatagram, RevocableStream};

/// Сборка клиента: маршрутизатор, направления, учёт.
pub struct Pipeline {
    router: Arc<Router>,
    outbounds: Arc<OutboundPool>,
    processes: Arc<dyn FlowOwnerResolver>,
    metrics: Arc<Metrics>,
    /// Живые соединения: после смены правил обрываются те, чьё решение изменилось.
    flows: Arc<LiveFlows>,
    /// Искать ли владельца соединения (системный вызов на каждое).
    resolve_process: bool,
    /// Шина решений; в проверках её нет.
    events: Option<EventBus>,
}

impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline")
            .field("router", &self.router)
            .field("resolve_process", &self.resolve_process)
            .finish_non_exhaustive()
    }
}

impl Pipeline {
    /// Собирает конвейер.
    pub fn new(
        router: Arc<Router>,
        outbounds: Arc<OutboundPool>,
        processes: Arc<dyn FlowOwnerResolver>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            router,
            outbounds,
            processes,
            metrics,
            flows: LiveFlows::new(),
            resolve_process: true,
            events: None,
        }
    }

    /// Общий с движком реестр живых соединений.
    pub fn with_flows(mut self, flows: Arc<LiveFlows>) -> Self {
        self.flows = flows;
        self
    }

    /// Куда сообщать о решениях по соединениям.
    pub fn with_events(mut self, events: EventBus) -> Self {
        self.events = Some(events);
        self
    }

    /// Включает или выключает поиск владельца соединения.
    pub fn with_process_lookup(mut self, enabled: bool) -> Self {
        self.resolve_process = enabled;
        self
    }

    /// Учёт трафика.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Маршрутизатор.
    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    /// Собирает контекст соединения: адреса, имя, владелец.
    pub fn context_of(&self, request: &InboundRequest) -> FlowContext {
        let mut flow =
            FlowContext::to_target(request.network, request.source, request.target.clone());

        if self.resolve_process
            && let Some(owner) = self.processes.owner_of(request.network, request.source)
        {
            flow = flow.with_process(owner);
        }

        flow
    }

    /// Направление под решение; не поднялось — соединение обрывается: напрямую
    /// оно ушло бы мимо тоннеля, которого от него ждали.
    fn outbound_for(&self, decision: &ResolvedDecision) -> Option<Arc<dyn Outbound>> {
        match decision {
            ResolvedDecision::Tunnel(id) => {
                let outbound = self.outbounds.get(id);
                if outbound.is_none() {
                    tracing::warn!(%id, "направление не поднято — соединение оборвано");
                }
                outbound
            }
            ResolvedDecision::Direct => Some(self.outbounds.direct()),
            ResolvedDecision::Block => None,
        }
    }

    /// Сообщает о решении одной строкой — в журнал и в окно.
    fn announce(&self, request: &InboundRequest, flow: &FlowContext, verdict: &Verdict) {
        let process = flow.process.as_ref().map(|owner| owner.name.to_string());
        let process_path = flow.process.as_ref().map(|owner| owner.path.to_string());

        tracing::debug!(
            target = %request.target,
            process = process.as_deref().unwrap_or("?"),
            decision = %verdict.decision,
            reason = %verdict.reason,
            "решение по соединению"
        );

        if let Some(events) = &self.events {
            events.emit(Event::decision(
                request.target.to_string(),
                process,
                process_path,
                verdict.decision.to_string(),
                Self::rule_of(&verdict.reason),
            ));
        }
    }

    /// Правило, по которому принято решение (в том числе из кэша).
    fn rule_of(reason: &Reason) -> Option<RuleId> {
        match reason {
            Reason::Rule { id, .. } => Some(id.clone()),
            Reason::Cached(inner) => Self::rule_of(inner),
            Reason::Mode | Reason::Fallback(_) => None,
        }
    }

    /// Имя направления для учёта.
    fn outbound_id(decision: &ResolvedDecision) -> OutboundId {
        match decision {
            ResolvedDecision::Tunnel(id) => id.clone(),
            ResolvedDecision::Direct | ResolvedDecision::Block => OutboundId::direct(),
        }
    }
}

#[async_trait]
impl InboundHandler for Pipeline {
    async fn open_tcp(
        &self,
        request: &InboundRequest,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let flow = self.context_of(request);
        let verdict = self.router.resolve(&flow);
        self.announce(request, &flow, &verdict);

        let Some(outbound) = self.outbound_for(&verdict.decision) else {
            return Err(ProtocolError::Unreachable(format!(
                "заблокировано: {}",
                verdict.reason
            )));
        };

        let outbound = self.outbounds.revive(outbound).await?;
        let stream = outbound.connect_tcp(&request.target).await?;
        let id = Self::outbound_id(&verdict.decision);
        let metered = Metered::new(stream, Arc::clone(&self.metrics), id);
        let lease = self.flows.register(flow, verdict.decision);
        Ok(Box::new(RevocableStream::new(metered, lease)))
    }

    async fn open_udp(
        &self,
        request: &InboundRequest,
    ) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        let flow = self.context_of(request);
        let verdict = self.router.resolve(&flow);
        self.announce(request, &flow, &verdict);

        let Some(outbound) = self.outbound_for(&verdict.decision) else {
            return Err(ProtocolError::Unreachable(format!(
                "заблокировано: {}",
                verdict.reason
            )));
        };

        let outbound = self.outbounds.revive(outbound).await?;
        // Иначе датаграммы (и DNS) терялись бы молча.
        let channel = if outbound.capabilities().udp {
            outbound.bind_udp().await?
        } else {
            tracing::warn!(
                outbound = %outbound.id(),
                "направление не поддерживает UDP — датаграммы пойдут напрямую"
            );
            self.outbounds.direct().bind_udp().await?
        };
        let lease = self.flows.register(flow, verdict.decision);
        Ok(Box::new(RevocableDatagram::new(channel, lease)))
    }
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::routing::TunnelMode;
    use penguin_core::address::SocketAddress;
    use penguin_core::network::Network;
    use penguin_dns::resolver::SystemResolver;
    use penguin_process::resolver::NoResolver;

    use super::*;
    use crate::direct::SystemDialer;

    fn pipeline(mode: TunnelMode) -> Pipeline {
        let dialer = Arc::new(SystemDialer::new(Arc::new(SystemResolver)));
        let outbounds = Arc::new(OutboundPool::new(dialer));
        let router = Arc::new(Router::passthrough(mode, OutboundId::new("home")));
        Pipeline::new(router, outbounds, Arc::new(NoResolver), Metrics::new())
    }

    fn request(target: &str) -> InboundRequest {
        InboundRequest {
            source: "127.0.0.1:50000".parse().expect("адрес"),
            target: target.parse().expect("адрес"),
            network: Network::Tcp,
        }
    }

    #[tokio::test]
    async fn direct_mode_reaches_a_real_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("сокет");
        let addr = listener.local_addr().expect("адрес");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let pipeline = pipeline(TunnelMode::Direct);
        let stream = pipeline
            .open_tcp(&request(&addr.to_string()))
            .await
            .expect("соединение открыто");
        drop(stream);

        assert_eq!(pipeline.metrics().total().connections, 1);
    }

    #[tokio::test]
    async fn missing_outbound_never_leaks_direct() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("сокет");
        let addr = listener.local_addr().expect("адрес");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let pipeline = pipeline(TunnelMode::Tunnel);
        let opened = pipeline.open_tcp(&request(&addr.to_string())).await;
        assert!(matches!(opened, Err(ProtocolError::Unreachable(_))));
    }

    #[tokio::test]
    async fn context_carries_the_target() {
        let pipeline = pipeline(TunnelMode::Direct);
        let flow = pipeline.context_of(&request("example.com:443"));
        assert_eq!(flow.destination, SocketAddress::domain("example.com", 443));
        assert!(flow.destination_ip().is_none());
    }

    #[tokio::test]
    async fn blocked_flow_is_refused_with_a_reason() {
        let pipeline = pipeline(TunnelMode::Direct);
        let router = Arc::new(Router::passthrough(
            TunnelMode::Direct,
            OutboundId::new("home"),
        ));
        let blocked = Pipeline {
            router,
            outbounds: Arc::clone(&pipeline.outbounds),
            processes: Arc::new(NoResolver),
            metrics: Metrics::new(),
            flows: LiveFlows::new(),
            resolve_process: false,
            events: None,
        };
        let decision = ResolvedDecision::Block;
        assert!(blocked.outbound_for(&decision).is_none());
    }
}
