//! Живые соединения и решения, с которыми их открыли. После смены правил решение
//! пересчитывается, и обрываются только соединения, чьё решение стало другим: по процессу,
//! адресу, имени — по чему угодно, что смотрит маршрутизатор.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use penguin_router::context::FlowContext;
use penguin_router::decision::ResolvedDecision;
use tokio_util::sync::CancellationToken;

/// Живые соединения конвейера.
#[derive(Debug, Default)]
pub struct LiveFlows {
    flows: Mutex<HashMap<u64, Flow>>,
    next: AtomicU64,
}

#[derive(Debug)]
struct Flow {
    context: FlowContext,
    decision: ResolvedDecision,
    revoked: CancellationToken,
}

/// Запись соединения: пока она жива, соединение числится живым.
#[derive(Debug)]
pub struct Lease {
    id: u64,
    flows: Arc<LiveFlows>,
    revoked: CancellationToken,
}

impl LiveFlows {
    /// Пустой реестр.
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    /// Записывает соединение с решением, по которому оно открыто.
    pub fn register(self: &Arc<Self>, context: FlowContext, decision: ResolvedDecision) -> Lease {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let revoked = CancellationToken::new();
        self.flows.lock().insert(
            id,
            Flow {
                context,
                decision,
                revoked: revoked.clone(),
            },
        );
        Lease {
            id,
            flows: Arc::clone(self),
            revoked,
        }
    }

    /// Обрывает соединения, которым `decide` даёт другое решение; возвращает их число.
    pub fn revise(&self, decide: impl Fn(&FlowContext) -> ResolvedDecision) -> usize {
        let flows = self.flows.lock();
        let mut revoked = 0;
        for flow in flows.values() {
            if !flow.revoked.is_cancelled() && decide(&flow.context) != flow.decision {
                flow.revoked.cancel();
                revoked += 1;
            }
        }
        revoked
    }

    /// Сколько соединений живо.
    pub fn len(&self) -> usize {
        self.flows.lock().len()
    }

    /// Живых соединений нет.
    pub fn is_empty(&self) -> bool {
        self.flows.lock().is_empty()
    }
}

impl Lease {
    /// Срабатывает, когда соединение надо оборвать.
    pub fn revoked(&self) -> &CancellationToken {
        &self.revoked
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.flows.flows.lock().remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use penguin_core::address::SocketAddress;
    use penguin_core::id::OutboundId;
    use penguin_core::network::Network;

    use super::*;

    fn flow(target: &str) -> FlowContext {
        FlowContext::to_target(
            Network::Tcp,
            "10.0.0.2:50000".parse().expect("адрес"),
            target.parse::<SocketAddress>().expect("адрес"),
        )
    }

    fn tunnel() -> ResolvedDecision {
        ResolvedDecision::Tunnel(OutboundId::new("home"))
    }

    #[test]
    fn only_flows_whose_decision_changed_are_revoked() {
        let flows = LiveFlows::new();
        let moved = flows.register(flow("1.1.1.1:443"), tunnel());
        let kept = flows.register(flow("8.8.8.8:443"), tunnel());

        let revoked = flows.revise(|context| {
            if context.destination == "1.1.1.1:443".parse().expect("адрес") {
                ResolvedDecision::Direct
            } else {
                tunnel()
            }
        });

        assert_eq!(revoked, 1);
        assert!(moved.revoked().is_cancelled());
        assert!(!kept.revoked().is_cancelled());
    }

    #[test]
    fn a_revoked_flow_is_not_counted_twice() {
        let flows = LiveFlows::new();
        let _lease = flows.register(flow("1.1.1.1:443"), tunnel());

        assert_eq!(flows.revise(|_| ResolvedDecision::Block), 1);
        assert_eq!(flows.revise(|_| ResolvedDecision::Block), 0);
    }

    #[test]
    fn a_closed_flow_leaves_the_registry() {
        let flows = LiveFlows::new();
        let lease = flows.register(flow("1.1.1.1:443"), tunnel());
        assert_eq!(flows.len(), 1);

        drop(lease);
        assert!(flows.is_empty());
    }
}
