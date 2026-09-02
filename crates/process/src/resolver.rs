//! `FlowOwnerResolver` — по локальному адресу и виду трафика найти процесс-владелец.
//!
//! Это и есть тот механизм, из-за которого раздельное тоннелирование в Penguin
//! обходится без драйвера ядра. TUN забирает трафик, соединение собирается в
//! пользовательском пространстве, и в этот момент известен его локальный порт.
//! По локальному порту систему можно спросить, чей он, — и она ответит.
//!
//! У способа есть цена, и её надо знать:
//!
//! - **гонка.** Очень короткое соединение успевает закрыться раньше, чем мы
//!   заглянем в таблицу. Тогда владелец неизвестен — и такое соединение
//!   **не** блокируется, а уходит по умолчанию режима: «не знаю чьё» и
//!   «ничьё» — разные вещи;
//! - **стоимость.** Таблица соединений читается целиком, поэтому читать её на
//!   каждое соединение нельзя. Отсюда кэш и настройка `routing.resolve_process`.

use std::net::SocketAddr;

use penguin_core::network::Network;

use crate::identity::ProcessIdentity;

/// Поиск владельца соединения.
///
/// Синхронный: под капотом системный вызов, который возвращается за
/// микросекунды. Заворачивать его в `async` значило бы обещать ожидание,
/// которого нет.
pub trait FlowOwnerResolver: Send + Sync + 'static {
    /// Кому принадлежит соединение с таким локальным адресом.
    ///
    /// `None` — владелец не найден. Это обычное дело, а не ошибка.
    fn owner_of(&self, network: Network, local: SocketAddr) -> Option<ProcessIdentity>;

    /// Сбрасывает всё, что было запомнено.
    ///
    /// Вызывается при переподключении: номера процессов к этому моменту могли
    /// смениться, а старый ответ увёл бы трафик не туда.
    fn invalidate(&self) {}
}

/// Резолвер, который никогда никого не находит.
///
/// Ставится, когда правил по процессам нет: чтение таблицы соединений стоит
/// системного вызова на каждое новое соединение, и платить за него, когда
/// результат всё равно никому не нужен, незачем.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoResolver;

impl FlowOwnerResolver for NoResolver {
    fn owner_of(&self, _network: Network, _local: SocketAddr) -> Option<ProcessIdentity> {
        None
    }
}

/// Резолвер для текущей платформы.
///
/// На платформе без реализации возвращается [`NoResolver`]: клиент обязан
/// работать и там, просто без правил по приложениям.
pub fn system_resolver() -> Box<dyn FlowOwnerResolver> {
    #[cfg(windows)]
    {
        Box::new(crate::platform::windows::WindowsResolver::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(crate::platform::linux::LinuxResolver::new())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
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
