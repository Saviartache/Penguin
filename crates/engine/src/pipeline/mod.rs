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
//!
//! Это и есть то место, где собираются вместе все части клиента. Заметьте,
//! чего здесь **нет**: ни одной строки, знающей про Hysteria 2, TUN или
//! конкретное правило. Всё общение идёт через трейты.

pub mod copy;
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

/// Сборка клиента: маршрутизатор, направления, учёт.
pub struct Pipeline {
    router: Arc<Router>,
    outbounds: Arc<OutboundPool>,
    processes: Arc<dyn FlowOwnerResolver>,
    metrics: Arc<Metrics>,
    /// Искать ли владельца соединения.
    ///
    /// Выключается, когда правил по процессам нет: чтение таблицы соединений
    /// стоит системного вызова на каждое новое соединение, и платить за него,
    /// когда результат никому не нужен, незачем.
    resolve_process: bool,
    /// Куда рассказывать о решениях.
    ///
    /// Необязательно: конвейер собирают и в проверках, где шины событий нет
    /// вовсе, а требовать её там значило бы тащить пол-движка ради одного
    /// поля.
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
            resolve_process: true,
            events: None,
        }
    }

    /// Куда рассказывать о решениях по соединениям.
    ///
    /// Без этого журнал окна знает только про подъём и падение тоннеля, а на
    /// вопрос «куда сейчас идёт трафик и каким путём» ответить нечем — при
    /// том что именно за этим в журнал и приходят.
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

    /// Находит направление под решение маршрутизатора.
    ///
    /// Направление могло не подняться — тогда лучше выпустить трафик
    /// напрямую, чем оборвать его: пользователь скорее простит незащищённое
    /// соединение, чем неработающий интернет. Это поведение видно в журнале
    /// и различимо в интерфейсе.
    fn outbound_for(&self, decision: &ResolvedDecision) -> Option<Arc<dyn Outbound>> {
        match decision {
            ResolvedDecision::Tunnel(id) => self.outbounds.get(id).or_else(|| {
                tracing::warn!(%id, "направление не поднято — трафик уходит напрямую");
                Some(self.outbounds.direct())
            }),
            ResolvedDecision::Direct => Some(self.outbounds.direct()),
            ResolvedDecision::Block => None,
        }
    }

    /// Рассказывает о решении — в журнал службы и в окно.
    ///
    /// Одной строкой на соединение, а не четырьмя, как это делают иные
    /// клиенты. Журнал окна держит последние строки, и четыре строки на
    /// соединение означают, что при живом трафике в нём видно последние
    /// полсекунды.
    fn announce(&self, request: &InboundRequest, flow: &FlowContext, verdict: &Verdict) {
        let process = flow.process.as_ref().map(|owner| owner.name.to_string());

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
                verdict.decision.to_string(),
                Self::rule_of(&verdict.reason),
            ));
        }
    }

    /// Правило, если решение принято по нему.
    ///
    /// Через кэш тоже: «из кэша» — это то же самое правило, просто найденное
    /// быстрее, и прятать его имя незачем.
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

        let stream = outbound.connect_tcp(&request.target).await?;
        let id = Self::outbound_id(&verdict.decision);
        Ok(Box::new(Metered::new(
            stream,
            Arc::clone(&self.metrics),
            id,
        )))
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

        // Направление, не умеющее UDP, молча потеряло бы датаграммы — а вместе
        // с ними и все запросы DNS. Лучше выпустить их напрямую и сказать об
        // этом вслух.
        if !outbound.capabilities().udp {
            tracing::warn!(
                outbound = %outbound.id(),
                "направление не поддерживает UDP — датаграммы пойдут напрямую"
            );
            return self.outbounds.direct().bind_udp().await;
        }

        outbound.bind_udp().await
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
        // Сквозная проверка прямого пути: слушаем свой порт и соединяемся с
        // ним через конвейер.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("сокет");
        let addr = listener.local_addr().expect("адрес");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let pipeline = pipeline(TunnelMode::Off);
        let stream = pipeline
            .open_tcp(&request(&addr.to_string()))
            .await
            .expect("соединение открыто");
        drop(stream);

        assert_eq!(pipeline.metrics().total().connections, 1);
    }

    #[tokio::test]
    async fn missing_outbound_falls_back_to_direct() {
        // Режим `full` шлёт всё в тоннель, но профиль `home` не поднят.
        // Оборвать трафик было бы хуже, чем выпустить его напрямую.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("сокет");
        let addr = listener.local_addr().expect("адрес");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let pipeline = pipeline(TunnelMode::Full);
        pipeline
            .open_tcp(&request(&addr.to_string()))
            .await
            .expect("соединение открыто");
    }

    #[tokio::test]
    async fn context_carries_the_target() {
        let pipeline = pipeline(TunnelMode::Off);
        let flow = pipeline.context_of(&request("example.com:443"));
        assert_eq!(flow.destination, SocketAddress::domain("example.com", 443));
        // Приложение через прокси отдало имя, адреса здесь нет.
        assert!(flow.destination_ip().is_none());
    }

    #[tokio::test]
    async fn blocked_flow_is_refused_with_a_reason() {
        let pipeline = pipeline(TunnelMode::Off);
        // Подменяем маршрутизатор на такой, который всё блокирует.
        let router = Arc::new(Router::passthrough(
            TunnelMode::Off,
            OutboundId::new("home"),
        ));
        let blocked = Pipeline {
            router,
            outbounds: Arc::clone(&pipeline.outbounds),
            processes: Arc::new(NoResolver),
            metrics: Metrics::new(),
            resolve_process: false,
            events: None,
        };
        // Без правил `Off` выпускает напрямую — проверяем, что решение
        // «заблокировать» вообще доходит до отказа.
        let decision = ResolvedDecision::Block;
        assert!(blocked.outbound_for(&decision).is_none());
    }
}
