//! `FlowOwnerResolver` — процесс-владелец по локальному адресу. Таблица
//! читается целиком, поэтому есть кэш и настройка `routing.resolve_process`.

use std::net::SocketAddr;

use penguin_core::network::Network;

use crate::identity::ProcessIdentity;

/// Поиск владельца соединения. Синхронный: системный вызов быстрый.
pub trait FlowOwnerResolver: Send + Sync + 'static {
    /// Владелец соединения с таким локальным адресом; `None` — не найден (не ошибка).
    fn owner_of(&self, network: Network, local: SocketAddr) -> Option<ProcessIdentity>;

    /// Сбрасывает запомненное; вызывается при переподключении.
    fn invalidate(&self) {}
}

/// Резолвер, который никого не находит; ставится, когда правил по процессам нет.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoResolver;

impl FlowOwnerResolver for NoResolver {
    fn owner_of(&self, _network: Network, _local: SocketAddr) -> Option<ProcessIdentity> {
        None
    }
}

/// Резолвер для текущей платформы; без реализации — [`NoResolver`].
pub fn system_resolver() -> Box<dyn FlowOwnerResolver> {
    #[cfg(windows)]
    {
        Box::new(crate::platform::windows::WindowsResolver::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(crate::platform::linux::LinuxResolver::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(crate::platform::macos::MacosResolver::new())
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        tracing::warn!("правила по приложениям на этой платформе не поддерживаются");
        Box::new(NoResolver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_resolver_finds_nothing() {
        let local: SocketAddr = "127.0.0.1:1234".parse().expect("адрес");
        assert!(NoResolver.owner_of(Network::Tcp, local).is_none());
    }
}
