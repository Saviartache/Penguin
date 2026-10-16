//! Windows: таблица соединений `GetTcpTable` и сброс `SetTcpEntry` (`MIB_TCP_STATE_DELETE_TCB`).

use std::net::{Ipv4Addr, SocketAddrV4};

use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetTcpTable, MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, MIB_TCPROW_LH, MIB_TCPTABLE,
    SetTcpEntry,
};

use crate::error::{PlatformError, PlatformResult};

/// Таблица растёт между вызовами; столько раз переспросить размер достаточно.
const ATTEMPTS: usize = 4;

pub(super) fn reset_tcp(selected: &dyn Fn(SocketAddrV4) -> bool) -> PlatformResult<usize> {
    let mut reset = 0;
    for row in table()? {
        #[allow(unsafe_code, reason = "поле объединения из таблицы системы")]
        // SAFETY: оба поля объединения — одно число.
        let state = unsafe { row.Anonymous.dwState };
        if state != MIB_TCP_STATE_ESTAB.0.cast_unsigned() || !selected(remote_of(&row)) {
            continue;
        }

        let mut kill = row;
        kill.Anonymous.dwState = MIB_TCP_STATE_DELETE_TCB.0.cast_unsigned();
        #[allow(unsafe_code, reason = "сброс соединения")]
        // SAFETY: `kill` — строка таблицы системы, живёт до конца вызова.
        let code = unsafe { SetTcpEntry(&kill) };
        match code {
            0 => reset += 1,
            code if code == ERROR_ACCESS_DENIED.0 => {
                return Err(PlatformError::PermissionDenied(
                    "сброс соединений".to_owned(),
                ));
            }
            // Соединение закрылось само, пока до него дошла очередь.
            code => tracing::debug!(code, "соединение не сброшено"),
        }
    }
    Ok(reset)
}

/// Строки таблицы соединений TCP поверх IPv4.
#[allow(unsafe_code, reason = "таблица соединений системы")]
fn table() -> PlatformResult<Vec<MIB_TCPROW_LH>> {
    let mut size = 0u32;
    for _ in 0..ATTEMPTS {
        // `u32`: таблица выровнена по четыре байта.
        let mut buffer = vec![0u32; (size as usize).div_ceil(4).max(1)];
        // SAFETY: буфер не меньше `size` байт и выровнен для `MIB_TCPTABLE`.
        let code = unsafe { GetTcpTable(Some(buffer.as_mut_ptr().cast()), &mut size, false) };
        if code == ERROR_INSUFFICIENT_BUFFER.0 {
            continue;
        }
        if code != NO_ERROR.0 {
            return Err(PlatformError::Route(format!(
                "таблица соединений: код {code}"
            )));
        }
        // SAFETY: система заполнила заголовок и `dwNumEntries` строк за ним.
        let rows = unsafe {
            let table = &*buffer.as_ptr().cast::<MIB_TCPTABLE>();
            std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
        };
        return Ok(rows.to_vec());
    }
    Err(PlatformError::Route(
        "таблица соединений растёт быстрее, чем читается".to_owned(),
    ))
}

/// Удалённый адрес строки: адрес и порт лежат в сетевом порядке.
fn remote_of(row: &MIB_TCPROW_LH) -> SocketAddrV4 {
    let address = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
    #[allow(clippy::cast_possible_truncation, reason = "порт — младшие 16 бит")]
    let port = u16::from_be(row.dwRemotePort as u16);
    SocketAddrV4::new(address, port)
}
