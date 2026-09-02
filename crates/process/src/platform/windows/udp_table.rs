//! `GetExtendedUdpTable` — то же для UDP.
//!
//! Устроено так же, как таблица TCP, но запись короче: у UDP нет удалённого
//! конца и нет состояния — только локальный адрес и владелец.

#![allow(unsafe_code, reason = "чтение системной таблицы переменной длины")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID,
    MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::table::{Entry, query_table, rows_of};
use super::tcp_table::port_of;

/// Читает таблицу UDP-сокетов IPv4 и IPv6.
pub fn snapshot() -> Vec<Entry> {
    let mut entries = read_v4();
    entries.extend(read_v6());
    entries
}

fn read_v4() -> Vec<Entry> {
    let Some(buffer) = query_table(|buf, size| unsafe {
        let table = (!buf.is_null()).then_some(buf);
        WIN32_ERROR(GetExtendedUdpTable(
            table,
            size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ))
    }) else {
        return Vec::new();
    };

    let table = buffer.as_ptr().cast::<MIB_UDPTABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { rows_of::<MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID>(table, count) };

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
        WIN32_ERROR(GetExtendedUdpTable(
            table,
            size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ))
    }) else {
        return Vec::new();
    };

    let table = buffer.as_ptr().cast::<MIB_UDP6TABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { rows_of::<MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID>(table, count) };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_finds_a_bound_socket() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("сокет");
        let local = socket.local_addr().expect("адрес");
        let ours = std::process::id();

        let found = snapshot()
            .into_iter()
            .any(|entry| entry.local.port() == local.port() && entry.pid == ours);
        assert!(found, "свой же сокет {local} не найден в таблице UDP");
    }
}
