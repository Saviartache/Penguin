//! `GetExtendedTcpTable` — сопоставление TCP-соединения и pid.
//!
//! Таблица возвращается как структура переменной длины: сначала число
//! записей, следом сами записи подряд. Прочитать её без арифметики по
//! указателям нельзя — отсюда `unsafe` в этом файле.
//!
//! Порты в записях лежат в сетевом порядке байт внутри `DWORD`. Забыть про
//! это — классическая ошибка: порт 443 превращается в 47873, и владелец
//! никогда не находится.

#![allow(unsafe_code, reason = "чтение системной таблицы переменной длины")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::table::{Entry, query_table, rows_of};

/// Читает таблицу TCP-соединений IPv4 и IPv6.
pub fn snapshot() -> Vec<Entry> {
    let mut entries = read_v4();
    entries.extend(read_v6());
    entries
}

fn read_v4() -> Vec<Entry> {
    let Some(buffer) = query_table(|buf, size| unsafe {
        let table = (!buf.is_null()).then_some(buf);
        WIN32_ERROR(GetExtendedTcpTable(
            table,
            size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ))
    }) else {
        return Vec::new();
    };

    // Заголовок таблицы — число записей; за ним подряд сами записи.
    let table = buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { rows_of::<MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID>(table, count) };

    rows.iter()
        .map(|row| Entry {
            local: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr))),
                port_of(row.dwLocalPort),
            ),
            pid: row.dwOwningPid,
        })
        .collect()
}

fn read_v6() -> Vec<Entry> {
    let Some(buffer) = query_table(|buf, size| unsafe {
        let table = (!buf.is_null()).then_some(buf);
        WIN32_ERROR(GetExtendedTcpTable(
            table,
            size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ))
    }) else {
        return Vec::new();
    };

    let table = buffer.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { rows_of::<MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID>(table, count) };

    rows.iter()
        .map(|row| Entry {
            local: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                port_of(row.dwLocalPort),
            ),
            pid: row.dwOwningPid,
        })
        .collect()
}

/// Достаёт порт из `DWORD`, где он лежит в сетевом порядке байт.
///
/// Свободная функция и с собственным тестом: перепутать порядок здесь легко,
/// а последствие — «владелец не найден» на каждом соединении, без единой
/// ошибки в журнале.
pub(super) fn port_of(raw: u32) -> u16 {
    u16::from_be_bytes([(raw & 0xFF) as u8, ((raw >> 8) & 0xFF) as u8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_is_read_in_network_order() {
        // 443 в сетевом порядке — это `0x01BB`, то есть байты `01 BB`,
        // лежащие в `DWORD` как `0x0000BB01`.
        assert_eq!(port_of(0x0000_BB01), 443);
        assert_eq!(port_of(0x0000_5000), 80);
        assert_eq!(port_of(0x0000_3500), 53);
    }

    #[test]
    fn snapshot_does_not_panic() {
        // Настоящая таблица системы. Проверяем не содержимое, а то, что
        // разбор переменной длины не выходит за границы.
        let entries = snapshot();
        for entry in entries.iter().take(50) {
            assert!(entry.local.port() > 0 || entry.pid == 0);
        }
    }

    #[test]
    fn snapshot_finds_a_listening_socket() {
        // Открываем свой сокет и ищем его в таблице: если разбор сдвинут хотя
        // бы на байт, найти его не удастся.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("сокет");
        let local = listener.local_addr().expect("адрес");
        let ours = std::process::id();

        let found = snapshot()
            .into_iter()
            .any(|entry| entry.local.port() == local.port() && entry.pid == ours);
        assert!(found, "свой же сокет {local} не найден в таблице");
    }
}
