//! Таблица активных сокетов и их переиспользование.
//!
//! Связывает три вещи, которые иначе разошлись бы: сокет внутри smoltcp,
//! пятёрку соединения и очереди наружу. Разойтись им нельзя — соединение
//! опознаётся по пятёрке, данные текут через очереди, а состояние живёт в
//! сокете.

use std::collections::HashMap;
use std::net::SocketAddr;

use bytes::Bytes;

use smoltcp::iface::SocketHandle;

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
    /// Соединение, ещё не отданное движку.
    ///
    /// Оно создаётся вместе с сокетом, но отдаётся только после завершения
    /// рукопожатия: до этого момента соединения ещё нет, и отдавать движку
    /// нечего.
    pub pending: Option<TcpConnection>,
    /// Блок, взятый у приложения, но ещё не отданный движку.
    ///
    /// Очередь к движку бывает полной. Выбросить в этот момент блок нельзя:
    /// он уже вынут из сокета, то есть для TCP отправлен и подтверждён.
    /// Пропажа середины потока рвёт TLS, и соединение начинается заново —
    /// снаружи это выглядит как медленный тоннель.
    pub to_engine: Option<Bytes>,
    /// Остаток блока движка, не поместившийся в сокет.
    ///
    /// `send_slice` записывает **сколько поместилось** и возвращает это
    /// число. Считать его успехом целиком — потерять хвост.
    pub to_app: Option<Bytes>,
    /// Приложение закрыло свою сторону.
    pub app_closed: bool,
    /// Движок закрыл свою.
    pub engine_closed: bool,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("key", &self.key)
            .field("pending", &self.pending.is_some())
            .field("app_closed", &self.app_closed)
            .field("engine_closed", &self.engine_closed)
            .finish()
    }
}

/// Таблица соединений стека.
#[derive(Debug, Default)]
pub struct ConnectionTable {
    by_handle: HashMap<SocketHandle, Entry>,
    by_key: HashMap<FlowKey, SocketHandle>,
}

impl ConnectionTable {
    /// Пустая таблица.
    pub fn new() -> Self {
        Self::default()
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
                pending: Some(connection),
                to_engine: None,
                to_app: None,
                app_closed: false,
                engine_closed: false,
            },
        );
    }

    /// Есть ли уже соединение с такой пятёркой.
    ///
    /// Повторный `SYN` — обычное дело: приложение перепосылает его, не
    /// дождавшись ответа. Заводить под него второй сокет нельзя.
    pub fn contains_key(&self, key: &FlowKey) -> bool {
        self.by_key.contains_key(key)
    }

    /// Соединение по сокету.
    pub fn get_mut(&mut self, handle: SocketHandle) -> Option<&mut Entry> {
        self.by_handle.get_mut(&handle)
    }

    /// Убирает соединение.
    pub fn remove(&mut self, handle: SocketHandle) -> Option<Entry> {
        let entry = self.by_handle.remove(&handle)?;
        self.by_key.remove(&entry.key);
        Some(entry)
    }

    /// Все сокеты таблицы.
    ///
    /// Отдельным списком, потому что цикл опроса меняет таблицу во время
    /// обхода: закрывшиеся соединения убираются прямо там.
    pub fn handles(&self) -> Vec<SocketHandle> {
        self.by_handle.keys().copied().collect()
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

    /// Заводит настоящий сокет: `SocketHandle` иначе не получить.
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
        // Приложение перепосылает `SYN`, не дождавшись ответа; второй сокет
        // под ту же пятёрку сломал бы соединение.
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
        // Забытая запись в одном из индексов означает, что пятёрка навсегда
        // считается занятой и новое соединение не установится.
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
    fn handles_snapshot_is_independent_of_the_table() {
        // Цикл опроса убирает записи прямо во время обхода; список сокетов
        // обязан пережить это.
        let mut sockets = SocketSet::new(Vec::new());
        let mut table = ConnectionTable::new();

        for port in 0..3u16 {
            let socket = handle(&mut sockets);
            let (conn, ends) =
                TcpConnection::new(key(50000 + port).source, key(50000 + port).destination);
            table.insert(socket, key(50000 + port), ends, conn);
        }

        let snapshot = table.handles();
        assert_eq!(snapshot.len(), 3);
        for socket in snapshot {
            table.remove(socket);
        }
        assert!(table.is_empty());
    }
}
