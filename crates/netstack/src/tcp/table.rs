//! Таблица активных сокетов: сокет smoltcp, пятёрка и очереди наружу.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use smoltcp::iface::SocketHandle;
use tokio::sync::Notify;

use super::conn::{ConnectionEnds, TcpConnection};

/// Пятёрка соединения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Адрес приложения.
    pub source: SocketAddr,
    /// Адрес назначения.
    pub destination: SocketAddr,
}

/// Соединение, живущее в стеке.
pub struct Entry {
    /// Сокет внутри smoltcp.
    pub handle: SocketHandle,
    /// Пятёрка.
    pub key: FlowKey,
    /// Очереди наружу.
    pub ends: ConnectionEnds,
    /// Соединение, ещё не отданное движку (отдаётся после рукопожатия).
    pub pending: Option<TcpConnection>,
    /// Блок, вынутый из сокета, но не принятый полной очередью; выбросить его нельзя — это дыра в потоке.
    pub to_engine: Option<Bytes>,
    /// Остаток блока движка, не поместившийся в сокет.
    pub to_socket: Option<Bytes>,
    /// Движок закрыл свою сторону.
    pub engine_closed: bool,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("key", &self.key)
            .field("pending", &self.pending.is_some())
            .field("engine_closed", &self.engine_closed)
            .finish()
    }
}

/// Таблица соединений стека.
#[derive(Debug, Default)]
pub struct ConnectionTable {
    by_handle: HashMap<SocketHandle, Entry>,
    by_key: HashMap<FlowKey, SocketHandle>,
    wake: Arc<Notify>,
}

impl ConnectionTable {
    /// Пустая таблица.
    pub fn new() -> Self {
        Self::default()
    }

    /// Будит цикл, когда у любого соединения таблицы появилась работа.
    pub fn wake(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }

    /// Добавляет соединение.
    pub fn insert(
        &mut self,
        handle: SocketHandle,
        key: FlowKey,
        ends: ConnectionEnds,
        connection: TcpConnection,
    ) {
        self.by_key.insert(key, handle);
        self.by_handle.insert(
            handle,
            Entry {
                handle,
                key,
                ends,
                pending: Some(connection.with_wake(Arc::clone(&self.wake))),
                to_engine: None,
                to_socket: None,
                engine_closed: false,
            },
        );
    }

    /// Есть ли соединение с такой пятёркой (повторный `SYN` второго сокета не заводит).
    pub fn contains_key(&self, key: &FlowKey) -> bool {
        self.by_key.contains_key(key)
    }

    /// Соединение по сокету.
    pub fn get_mut(&mut self, handle: SocketHandle) -> Option<&mut Entry> {
        self.by_handle.get_mut(&handle)
    }

    /// Все соединения для обхода; убирать их во время обхода нельзя.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut Entry)> {
        self.by_handle
            .iter_mut()
            .map(|(handle, entry)| (*handle, entry))
    }

    /// Убирает соединение.
    pub fn remove(&mut self, handle: SocketHandle) -> Option<Entry> {
        let entry = self.by_handle.remove(&handle)?;
        self.by_key.remove(&entry.key);
        Some(entry)
    }

    /// Сколько соединений живо.
    pub fn len(&self) -> usize {
        self.by_handle.len()
    }

    /// Таблица пуста.
    pub fn is_empty(&self) -> bool {
        self.by_handle.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use smoltcp::iface::SocketSet;
    use smoltcp::socket::tcp;

    use super::super::conn::TcpConnection;
    use super::*;

    fn key(port: u16) -> FlowKey {
        FlowKey {
            source: format!("10.0.0.2:{port}").parse().expect("адрес"),
            destination: "93.184.216.34:443".parse().expect("адрес"),
        }
    }

    /// Настоящий сокет: иначе `SocketHandle` не получить.
    fn handle(sockets: &mut SocketSet<'static>) -> SocketHandle {
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 64]),
            tcp::SocketBuffer::new(vec![0u8; 64]),
        );
        sockets.add(socket)
    }

    #[test]
    fn tracks_by_handle_and_by_key() {
        let mut sockets = SocketSet::new(Vec::new());
        let mut table = ConnectionTable::new();

        let first = handle(&mut sockets);
        let (conn, ends) = TcpConnection::new(key(50000).source, key(50000).destination);
        table.insert(first, key(50000), ends, conn);

        assert!(table.contains_key(&key(50000)));
        assert!(table.get_mut(first).is_some());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn repeated_syn_does_not_create_a_second_socket() {
        let mut sockets = SocketSet::new(Vec::new());
        let mut table = ConnectionTable::new();

        let socket = handle(&mut sockets);
        let (conn, ends) = TcpConnection::new(key(50000).source, key(50000).destination);
        table.insert(socket, key(50000), ends, conn);

        assert!(table.contains_key(&key(50000)));
        assert!(!table.contains_key(&key(50001)));
    }

    #[test]
    fn removal_clears_both_indexes() {
        let mut sockets = SocketSet::new(Vec::new());
        let mut table = ConnectionTable::new();

        let socket = handle(&mut sockets);
        let (conn, ends) = TcpConnection::new(key(50000).source, key(50000).destination);
        table.insert(socket, key(50000), ends, conn);

        table.remove(socket).expect("запись есть");
        assert!(!table.contains_key(&key(50000)));
        assert!(table.get_mut(socket).is_none());
        assert!(table.is_empty());
    }

    #[test]
    fn iteration_visits_every_connection() {
        let mut sockets = SocketSet::new(Vec::new());
        let mut table = ConnectionTable::new();

        for port in 0..3u16 {
            let socket = handle(&mut sockets);
            let (conn, ends) =
                TcpConnection::new(key(50000 + port).source, key(50000 + port).destination);
            table.insert(socket, key(50000 + port), ends, conn);
        }

        assert_eq!(table.iter_mut().count(), 3);
    }
}
